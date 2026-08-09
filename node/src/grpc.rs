use crate::command::config::current_network;
use crate::runtime::node::Node;
use crate::runtime::params::{CHAIN_NAME, COIN_NAME, PROTOCOL_STAGE, PROTOCOL_VERSION};
use crate::{PeerConnection, PeerState};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
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
    peers: Arc<Mutex<HashMap<SocketAddr, PeerState>>>,
    peer_connections: Arc<Mutex<HashMap<SocketAddr, PeerConnection>>>,
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
        let peer_count = self
            .peers
            .lock()
            .map(|peers| peers.len())
            .unwrap_or_default()
            + self
                .peer_connections
                .lock()
                .map(|connections| connections.len())
                .unwrap_or_default();
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
    peers: Arc<Mutex<HashMap<SocketAddr, PeerState>>>,
    peer_connections: Arc<Mutex<HashMap<SocketAddr, PeerConnection>>>,
    mining: bool,
    min_relay_fee: u64,
    market_fee: u64,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                eprintln!("[GRPC] runtime_failed error=\"{error}\"");
                return;
            }
        };
        runtime.block_on(async move {
            let service = GrpcNodeService {
                node,
                peers,
                peer_connections,
                mining,
                min_relay_fee,
                market_fee,
            };
            println!("[GRPC] listening addr={addr}");
            if let Err(error) = tonic::transport::Server::builder()
                .add_service(NodeRpcServer::new(service))
                .serve(addr)
                .await
            {
                eprintln!("[GRPC] failed error=\"{error}\"");
            }
        });
    })
}
