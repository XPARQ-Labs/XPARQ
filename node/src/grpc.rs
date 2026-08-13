use crate::command::config::current_network;
use crate::p2p::swarm::SwarmHandle;
use crate::runtime::node::Node;
use crate::runtime::params::{CHAIN_NAME, COIN_NAME, PROTOCOL_STAGE, PROTOCOL_VERSION};
use crate::{node_error, node_info};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tonic::{Request, Response, Status};
use xparq::block::Height;

pub mod proto {
    tonic::include_proto!("xparq.node.v1");
}

use proto::node_rpc_server::{NodeRpc, NodeRpcServer};
use proto::{GetStatusRequest, GetStatusResponse};

#[derive(Clone)]
struct GrpcNodeService {
    node: Arc<Mutex<Node>>,
    p2p_swarm: SwarmHandle,
    mining: bool,
    min_relay_fee: u64,
    market_fee: u64,
}

#[tonic::async_trait]
impl NodeRpc for GrpcNodeService {
    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        let node = self
            .node
            .lock()
            .map_err(|_| Status::internal("node state lock poisoned"))?;
        let connection_stats = self.p2p_swarm.connection_stats();
        let peer_count = connection_stats.total;
        let height = node.tip_height().unwrap_or(Height(0)).0;
        let tip_hash = node
            .tip_hash()
            .map(|hash| hex::encode(hash.0))
            .unwrap_or_else(|| "none".to_string());
        Ok(Response::new(GetStatusResponse {
            network: current_network().to_string(),
            chain_name: CHAIN_NAME.to_string(),
            coin_name: COIN_NAME.to_string(),
            protocol_stage: PROTOCOL_STAGE.to_string(),
            protocol_version: PROTOCOL_VERSION as u32,
            height,
            tip_hash,
            peers: peer_count as u64,
            mining: self.mining,
            min_relay_fee: self.min_relay_fee,
            market_fee: self.market_fee,
        }))
    }
}

pub fn start_grpc_server(
    addr: SocketAddr,
    node: Arc<Mutex<Node>>,
    p2p_swarm: SwarmHandle,
    mining: bool,
    min_relay_fee: u64,
    market_fee: u64,
) -> Result<std::thread::JoinHandle<()>, String> {
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let handle = std::thread::Builder::new()
        .name("xparq-grpc".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(format!("gRPC runtime failed: {error}")));
                    node_error!("GRPC", "runtime_failed error={error:?}");
                    return;
                }
            };
            runtime.block_on(async move {
                let service = GrpcNodeService {
                    node,
                    p2p_swarm,
                    mining,
                    min_relay_fee,
                    market_fee,
                };
                let listener = match tokio::net::TcpListener::bind(addr).await {
                    Ok(listener) => listener,
                    Err(error) => {
                        let _ = ready_tx
                            .send(Err(format!("failed to bind gRPC listener {addr}: {error}")));
                        return;
                    }
                };
                let incoming = futures_util::stream::unfold(listener, |listener| async move {
                    Some((listener.accept().await.map(|(stream, _)| stream), listener))
                });
                node_info!("GRPC", "listening addr={addr}");
                let _ = ready_tx.send(Ok(()));
                if let Err(error) = tonic::transport::Server::builder()
                    .add_service(NodeRpcServer::new(service))
                    .serve_with_incoming_shutdown(incoming, async {
                        while !crate::SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::SeqCst) {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    })
                    .await
                {
                    node_error!("GRPC", "server_failed error={error:?}");
                }
            });
        })
        .map_err(|error| format!("failed to spawn gRPC server: {error}"))?;
    match ready_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => Ok(handle),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(format!("timed out starting gRPC listener {addr}")),
    }
}
