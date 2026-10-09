//! Real TCP/Noise/Yamux request-slot and deadline regressions.
#![cfg(feature = "litep2p-devnet")]
use futures::StreamExt;
use litep2p::{
    Litep2p, PeerId,
    codec::ProtocolCodec,
    config::ConfigBuilder,
    protocol::{
        Direction, TransportEvent, TransportService, UserProtocol,
        request_response::{
            ConfigBuilder as RequestBuilder, RequestResponseEvent, RequestResponseHandle,
        },
    },
    substream::Substream,
    transport::tcp::config::Config as TcpConfig,
    types::{SubstreamId, multiaddr::Multiaddr, protocol::ProtocolName},
};
use std::{collections::HashMap, future::Future, pin::Pin, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
const PROTOCOL: &str = "/xparq/devnet/blocks/2";
const DEADLINE: Duration = Duration::from_millis(500);
const WAIT: Duration = Duration::from_secs(4);
const MAX_RESPONSE: usize = 8 * 1024 * 1024;

struct RawProtocol {
    commands: mpsc::Receiver<oneshot::Sender<Substream>>,
    connected: oneshot::Sender<()>,
    peer: PeerId,
}
impl UserProtocol for RawProtocol {
    fn protocol(&self) -> ProtocolName {
        ProtocolName::from(PROTOCOL)
    }
    fn codec(&self) -> ProtocolCodec {
        ProtocolCodec::UnsignedVarint(Some(MAX_RESPONSE))
    }
    fn run<'async_trait>(
        self: Box<Self>,
        mut service: TransportService,
    ) -> Pin<Box<dyn Future<Output = litep2p::Result<()>> + Send + 'async_trait>>
    where
        Self: 'async_trait,
    {
        Box::pin(async move {
            let mut commands = self.commands;
            let mut connected = Some(self.connected);
            let mut pending = HashMap::<SubstreamId, oneshot::Sender<Substream>>::new();
            loop {
                tokio::select! {
                    command = commands.recv() => match command {
                        Some(reply) => { let id = service.open_substream(self.peer)?; pending.insert(id, reply); }
                        None => return Ok(()),
                    },
                    event = service.next() => match event {
                        Some(TransportEvent::ConnectionEstablished { .. }) => { if let Some(ready) = connected.take() { let _ = ready.send(()); } }
                        Some(TransportEvent::SubstreamOpened { direction: Direction::Outbound(id), substream, .. }) => {
                            if let Some(reply) = pending.remove(&id) { let _ = reply.send(substream); }
                        }
                        Some(TransportEvent::SubstreamOpenFailure { substream, .. }) => { pending.remove(&substream); }
                        None => return Ok(()),
                        _ => {}
                    }
                }
            }
        })
    }
}
struct RawPeer {
    id: PeerId,
    commands: mpsc::Sender<oneshot::Sender<Substream>>,
    driver: JoinHandle<()>,
}
impl Drop for RawPeer {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
impl RawPeer {
    async fn connect(address: Multiaddr, peer: PeerId) -> Self {
        Self::connect_with_identity(address, peer, litep2p::crypto::ed25519::Keypair::generate())
            .await
    }
    async fn connect_with_identity(
        address: Multiaddr,
        peer: PeerId,
        identity: litep2p::crypto::ed25519::Keypair,
    ) -> Self {
        let (commands, receiver) = mpsc::channel(8);
        let (ready, connected) = oneshot::channel();
        let mut network = Litep2p::new(
            ConfigBuilder::new()
                .with_keypair(identity)
                .with_tcp(TcpConfig {
                    listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                    ..Default::default()
                })
                .with_user_protocol(Box::new(RawProtocol {
                    commands: receiver,
                    connected: ready,
                    peer,
                }))
                .build(),
        )
        .unwrap();
        network.dial_address(address).await.unwrap();
        let id = *network.local_peer_id();
        let driver = tokio::spawn(async move { while network.next_event().await.is_some() {} });
        tokio::time::timeout(WAIT, connected)
            .await
            .unwrap()
            .unwrap();
        Self {
            id,
            commands,
            driver,
        }
    }
    async fn open(&self) -> Substream {
        let (reply, stream) = oneshot::channel();
        self.commands.send(reply).await.unwrap();
        tokio::time::timeout(WAIT, stream).await.unwrap().unwrap()
    }
}
async fn closed(stream: &mut Substream) {
    let result = tokio::time::timeout(WAIT, stream.next())
        .await
        .expect("request slot was not released");
    assert!(
        matches!(result, None | Some(Err(_))),
        "unexpected response to rejected/stalled request"
    );
}
async fn received(requests: &mut RequestResponseHandle) -> litep2p::types::RequestId {
    match tokio::time::timeout(WAIT, requests.next())
        .await
        .unwrap()
        .unwrap()
    {
        RequestResponseEvent::RequestReceived {
            request_id,
            request,
            ..
        } => {
            assert_eq!(request, vec![1]);
            request_id
        }
        other => panic!("unexpected request event: {other:?}"),
    }
}
async fn response(peer: &RawPeer, requests: &mut RequestResponseHandle) {
    let mut stream = peer.open().await;
    stream.send_framed(vec![1].into()).await.unwrap();
    let id = received(requests).await;
    requests.send_response(id, vec![9; 4096]);
    let bytes = tokio::time::timeout(WAIT, stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(bytes.as_ref(), &[9; 4096]);
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_slots_span_reads_application_wait_and_response_writes() {
    let (config, mut requests) = RequestBuilder::new(ProtocolName::from(PROTOCOL))
        .with_max_size(MAX_RESPONSE)
        .with_timeout(DEADLINE)
        .with_max_concurrent_inbound_requests(8)
        .with_max_inbound_requests_per_peer(2)
        .with_inbound_timeout(DEADLINE)
        .with_max_inbound_request_size(33)
        .build();
    let mut server = Litep2p::new(
        ConfigBuilder::new()
            .with_tcp(TcpConfig {
                listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                ..Default::default()
            })
            .with_request_response_protocol(config)
            .build(),
    )
    .unwrap();
    let address = server.listen_addresses().next().unwrap().clone();
    let server_peer = *server.local_peer_id();
    let driver = tokio::spawn(async move { while server.next_event().await.is_some() {} });
    let identity = litep2p::crypto::ed25519::Keypair::generate();
    let attacker =
        RawPeer::connect_with_identity(address.clone(), server_peer, identity.clone()).await;
    let healthy = RawPeer::connect(address.clone(), server_peer).await;

    // One peer cannot fill the eight global slots with unread frames.
    let mut silent = attacker.open().await;
    let mut trickle = attacker.open().await;
    // Partial frame bytes do not restart the absolute read deadline.
    trickle.write_all(&[16, 1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut excess = attacker.open().await;
    closed(&mut excess).await;
    response(&healthy, &mut requests).await;
    closed(&mut silent).await;
    closed(&mut trickle).await;
    response(&attacker, &mut requests).await;

    // Oversized declared length is rejected even without a payload.
    let mut oversized = attacker.open().await;
    oversized.write_all(&[34]).await.unwrap();
    closed(&mut oversized).await;
    response(&attacker, &mut requests).await;

    // Holding application response handles cannot retain a peer's slots forever.
    let mut waiting = attacker.open().await;
    waiting.send_framed(vec![1].into()).await.unwrap();
    let id = received(&mut requests).await;
    closed(&mut waiting).await;
    requests.reject_request(id); // Release the application's obsolete sender too.
    response(&attacker, &mut requests).await;

    // Both permits remain held while large responses block on the remote window.
    let mut blocked = Vec::new();
    for _ in 0..2 {
        let mut stream = attacker.open().await;
        stream.send_framed(vec![1].into()).await.unwrap();
        let id = received(&mut requests).await;
        requests.send_response(id, vec![7; MAX_RESPONSE]);
        blocked.push(stream);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut excess = attacker.open().await;
    closed(&mut excess).await;
    response(&healthy, &mut requests).await;
    tokio::time::sleep(DEADLINE + Duration::from_millis(100)).await;
    response(&attacker, &mut requests).await;
    drop(blocked);

    // An old application-wait permit cannot release a new connection's slots.
    let mut obsolete_stream = attacker.open().await;
    obsolete_stream.send_framed(vec![1].into()).await.unwrap();
    let obsolete = received(&mut requests).await;
    drop(obsolete_stream);
    drop(attacker);
    tokio::time::sleep(DEADLINE / 2).await;
    let reconnected = RawPeer::connect_with_identity(address, server_peer, identity).await;
    let mut first = reconnected.open().await;
    let mut second = reconnected.open().await;
    tokio::time::sleep(DEADLINE / 2 + Duration::from_millis(50)).await;
    let mut excess = reconnected.open().await;
    closed(&mut excess).await;
    response(&healthy, &mut requests).await;
    closed(&mut first).await;
    closed(&mut second).await;
    requests.reject_request(obsolete);
    response(&reconnected, &mut requests).await;
    driver.abort();
}

// Exercise the production limiter over real frames with a deterministic quota clock.
const MAX_STORED_BLOCK_SIZE: usize = kernel::block::MAX_BLOCK_SIZE + 1024;
#[path = "../src/node/response_budget.rs"]
mod response_budget;

#[tokio::test(flavor = "multi_thread")]
async fn exhausted_bulk_sender_cannot_consume_another_peers_response_capacity() {
    use response_budget::{ResponseBudget, ResponseClass};
    let (config, mut requests) = RequestBuilder::new(ProtocolName::from(PROTOCOL))
        .with_max_size(MAX_STORED_BLOCK_SIZE + 1)
        .with_timeout(WAIT)
        .with_max_concurrent_inbound_requests(8)
        .with_max_inbound_requests_per_peer(2)
        .with_inbound_timeout(WAIT)
        .with_max_inbound_request_size(33)
        .build();
    let mut server = Litep2p::new(
        ConfigBuilder::new()
            .with_tcp(TcpConfig {
                listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                ..Default::default()
            })
            .with_request_response_protocol(config)
            .build(),
    )
    .unwrap();
    let address = server.listen_addresses().next().unwrap().clone();
    let peer = *server.local_peer_id();
    let driver = tokio::spawn(async move { while server.next_event().await.is_some() {} });
    let bulk = RawPeer::connect(address.clone(), peer).await;
    let healthy = RawPeer::connect(address, peer).await;
    let now = std::time::Instant::now();
    let mut budget = ResponseBudget::default();
    let mut bulk_peer = None;
    for index in 0..18 {
        let client = if index == 17 { &healthy } else { &bulk };
        let mut stream = client.open().await;
        stream.send_framed(vec![1].into()).await.unwrap();
        let (id, sender) = match tokio::time::timeout(WAIT, requests.next())
            .await
            .unwrap()
            .unwrap()
        {
            RequestResponseEvent::RequestReceived {
                peer, request_id, ..
            } => (request_id, peer),
            other => panic!("unexpected request: {other:?}"),
        };
        if index == 0 {
            bulk_peer = Some(sender);
        }
        if index == 17 {
            assert_ne!(bulk_peer, Some(sender));
        }
        let payload = if index < 17 { 1024 * 1024 - 3 } else { 4096 };
        if budget.admit(sender, ResponseClass::Block, payload, now) {
            assert_ne!(index, 16, "exhausted peer was admitted");
            requests.send_response(id, vec![9; payload]);
            let data = tokio::time::timeout(WAIT, stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(data.len(), payload);
        } else {
            assert_eq!(index, 16, "healthy peer or permitted response was rejected");
            requests.reject_request(id);
            closed(&mut stream).await;
        }
    }
    assert!(budget.admit(bulk_peer.unwrap(), ResponseClass::Control, 512, now));
    driver.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn global_slot_waiters_are_bounded_fifo_and_expire_without_reading() {
    let (config, mut requests) = RequestBuilder::new(ProtocolName::from(PROTOCOL))
        .with_max_size(MAX_RESPONSE)
        .with_timeout(WAIT)
        .with_max_concurrent_inbound_requests(2)
        .with_max_pending_inbound_requests(2)
        .with_max_inbound_requests_per_peer(2)
        .with_inbound_timeout(DEADLINE)
        .with_max_inbound_request_size(33)
        .build();
    let mut server = Litep2p::new(
        ConfigBuilder::new()
            .with_tcp(TcpConfig {
                listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                ..Default::default()
            })
            .with_request_response_protocol(config)
            .build(),
    )
    .unwrap();
    let address = server.listen_addresses().next().unwrap().clone();
    let id = *server.local_peer_id();
    let driver = tokio::spawn(async move { while server.next_event().await.is_some() {} });
    struct Driver(JoinHandle<()>);
    impl Drop for Driver {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _driver = Driver(driver);
    let attacker = RawPeer::connect(address.clone(), id).await;
    let healthy = RawPeer::connect(address.clone(), id).await;
    let other = RawPeer::connect(address.clone(), id).await;
    let overflow = RawPeer::connect(address, id).await;
    let mut active = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..2 {
        let mut stream = attacker.open().await;
        stream.send_framed(vec![1].into()).await.unwrap();
        ids.push(received(&mut requests).await);
        active.push(stream);
    }
    let mut first = healthy.open().await;
    first.send_framed(vec![1].into()).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), requests.next())
            .await
            .is_err()
    );
    let mut second = other.open().await;
    second.send_framed(vec![1].into()).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), requests.next())
            .await
            .is_err()
    );
    let mut excess = overflow.open().await;
    let _ = excess.send_framed(vec![1].into()).await;
    closed(&mut excess).await;
    // The attacker's peer permits also cover waiting and application response wait.
    closed(&mut attacker.open().await).await;
    requests.send_response(ids[0], vec![9; 4096]);
    assert_eq!(
        tokio::time::timeout(WAIT, active[0].next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .len(),
        4096
    );
    let first_id = match tokio::time::timeout(WAIT, requests.next())
        .await
        .unwrap()
        .unwrap()
    {
        RequestResponseEvent::RequestReceived {
            peer, request_id, ..
        } => {
            assert_eq!(peer, healthy.id, "later arrival bypassed the FIFO waiter");
            request_id
        }
        event => panic!("unexpected waiter event: {event:?}"),
    };
    // Retain both application slots, so the remaining waiter must expire.
    closed(&mut second).await;
    // Expiry must not release either of the globally active requests.
    let mut expired_again = other.open().await;
    expired_again.send_framed(vec![1].into()).await.unwrap();
    closed(&mut expired_again).await;
    requests.send_response(first_id, vec![9; 4096]);
    assert_eq!(
        tokio::time::timeout(WAIT, first.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .len(),
        4096
    );
    response(&other, &mut requests).await;
    requests.reject_request(ids[1]);
}
