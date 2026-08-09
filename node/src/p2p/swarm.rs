use crate::runtime::network::message::RejectReason;
use crate::runtime::network::{NetworkMessage, PeerInfo, handle_message};
use crate::runtime::node::Node;
use crate::runtime::params::MAX_NETWORK_MESSAGE_SIZE;
use borsh::{BorshDeserialize, BorshSerialize};
use futures_util::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use libp2p::identify;
use libp2p::kad::{self, store::MemoryStore};
use libp2p::ping;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder, noise, tcp, yamux};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc;

const XPARQ_PROTOCOL: StreamProtocol = StreamProtocol::new("/xparq/borsh/1");
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(300);
const COMMAND_BUFFER: usize = 1024;

static GLOBAL_SWARM: OnceLock<SwarmHandle> = OnceLock::new();

#[derive(Clone)]
pub struct SwarmHandle {
    commands: mpsc::Sender<Command>,
}

impl SwarmHandle {
    pub fn connect(&self, addr: SocketAddr) -> Result<(), String> {
        let (tx, rx) = std_mpsc::sync_channel(1);
        self.commands
            .blocking_send(Command::Connect { addr, result: tx })
            .map_err(|_| "libp2p swarm stopped".to_string())?;
        rx.recv_timeout(REQUEST_TIMEOUT)
            .map_err(|_| format!("libp2p connection timed out: {addr}"))?
    }

    pub fn request(
        &self,
        addr: SocketAddr,
        message: NetworkMessage,
    ) -> Result<Option<NetworkMessage>, String> {
        let (tx, rx) = std_mpsc::sync_channel(1);
        self.commands
            .blocking_send(Command::Request {
                addr,
                message,
                result: tx,
            })
            .map_err(|_| "libp2p swarm stopped".to_string())?;
        rx.recv_timeout(REQUEST_TIMEOUT)
            .map_err(|_| format!("libp2p request timed out: {addr}"))?
    }

    pub fn disconnect(&self, addr: SocketAddr) {
        let _ = self.commands.blocking_send(Command::Disconnect(addr));
    }

    pub fn shutdown(&self) {
        let _ = self.commands.blocking_send(Command::Shutdown);
    }
}

pub fn global() -> Result<SwarmHandle, String> {
    GLOBAL_SWARM
        .get()
        .cloned()
        .ok_or_else(|| "libp2p swarm is not running".to_string())
}

pub fn start(
    listen_addrs: &[SocketAddr],
    bootstrap_addrs: &[SocketAddr],
    public_addrs: &[SocketAddr],
    identity_path: PathBuf,
    node: Arc<Mutex<Node>>,
    peers: Arc<Mutex<HashMap<SocketAddr, super::PeerState>>>,
) -> Result<SwarmHandle, String> {
    let (commands, receiver) = mpsc::channel(COMMAND_BUFFER);
    let handle = SwarmHandle { commands };
    let (ready_tx, ready_rx) = std_mpsc::sync_channel(1);
    let listen_addrs = listen_addrs.to_vec();
    let bootstrap_addrs = bootstrap_addrs.to_vec();
    let public_addrs = public_addrs.to_vec();

    thread::Builder::new()
        .name("xparq-libp2p".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(format!("libp2p runtime failed: {error}")));
                    return;
                }
            };
            runtime.block_on(run_swarm(
                listen_addrs,
                bootstrap_addrs,
                public_addrs,
                identity_path,
                node,
                peers,
                receiver,
                ready_tx,
            ));
        })
        .map_err(|error| format!("failed to start libp2p thread: {error}"))?;

    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| "libp2p startup timed out".to_string())??;
    GLOBAL_SWARM
        .set(handle.clone())
        .map_err(|_| "libp2p swarm was already started".to_string())?;
    Ok(handle)
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct WireRequest {
    message: NetworkMessage,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct WireResponse {
    message: Option<NetworkMessage>,
}

#[derive(Clone, Default)]
struct XparqCodec;

#[async_trait::async_trait]
impl request_response::Codec for XparqCodec {
    type Protocol = StreamProtocol;
    type Request = WireRequest;
    type Response = WireResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_borsh(io).await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_borsh(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_borsh(io, &request).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_borsh(io, &response).await
    }
}

async fn read_borsh<T, V>(io: &mut T) -> io::Result<V>
where
    T: AsyncRead + Unpin + Send,
    V: BorshDeserialize,
{
    let mut bytes = Vec::new();
    io.take((MAX_NETWORK_MESSAGE_SIZE + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > MAX_NETWORK_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "libp2p message too large",
        ));
    }
    borsh::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

async fn write_borsh<T, V>(io: &mut T, value: &V) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
    V: BorshSerialize,
{
    let bytes = borsh::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    if bytes.len() > MAX_NETWORK_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "libp2p message too large",
        ));
    }
    io.write_all(&bytes).await?;
    io.close().await
}

#[derive(NetworkBehaviour)]
struct XparqBehaviour {
    requests: request_response::Behaviour<XparqCodec>,
    identify: identify::Behaviour,
    kad: kad::Behaviour<MemoryStore>,
    ping: ping::Behaviour,
}

enum Command {
    Connect {
        addr: SocketAddr,
        result: std_mpsc::SyncSender<Result<(), String>>,
    },
    Request {
        addr: SocketAddr,
        message: NetworkMessage,
        result: std_mpsc::SyncSender<Result<Option<NetworkMessage>, String>>,
    },
    Disconnect(SocketAddr),
    Shutdown,
}

struct PendingRequest {
    message: NetworkMessage,
    result: std_mpsc::SyncSender<Result<Option<NetworkMessage>, String>>,
}

async fn run_swarm(
    listen_addrs: Vec<SocketAddr>,
    bootstrap_addrs: Vec<SocketAddr>,
    public_addrs: Vec<SocketAddr>,
    identity_path: PathBuf,
    node: Arc<Mutex<Node>>,
    peers: Arc<Mutex<HashMap<SocketAddr, super::PeerState>>>,
    mut commands: mpsc::Receiver<Command>,
    ready: std_mpsc::SyncSender<Result<(), String>>,
) {
    let mut swarm = match build_swarm(&identity_path) {
        Ok(swarm) => swarm,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    for addr in &listen_addrs {
        if let Err(error) = swarm.listen_on(socket_to_multiaddr(*addr)) {
            let _ = ready.send(Err(format!("libp2p listen failed on {addr}: {error}")));
            return;
        }
    }
    let mut bound_listeners = 0_usize;
    while bound_listeners < listen_addrs.len() {
        match tokio::time::timeout(Duration::from_secs(10), swarm.select_next_some()).await {
            Ok(libp2p::swarm::SwarmEvent::NewListenAddr { address, .. }) => {
                bound_listeners = bound_listeners.saturating_add(1);
                println!(
                    "[P2P] libp2p_listening peer_id={} addr={address}",
                    swarm.local_peer_id()
                );
            }
            Ok(_) => {}
            Err(_) => {
                let _ = ready.send(Err("libp2p listener startup timed out".to_string()));
                return;
            }
        }
    }
    for addr in public_addrs {
        swarm.add_external_address(socket_to_multiaddr(addr));
    }
    for addr in bootstrap_addrs {
        let _ = swarm.dial(socket_to_multiaddr(addr));
    }
    let _ = ready.send(Ok(()));

    let mut addr_to_peer = HashMap::<SocketAddr, PeerId>::new();
    let mut peer_to_addr = HashMap::<PeerId, SocketAddr>::new();
    let mut connect_waiters =
        HashMap::<SocketAddr, Vec<std_mpsc::SyncSender<Result<(), String>>>>::new();
    let mut queued = HashMap::<SocketAddr, Vec<PendingRequest>>::new();
    let mut outstanding = HashMap::new();
    let mut dialing = HashSet::<SocketAddr>::new();

    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break };
                match command {
                    Command::Connect { addr, result } => {
                        if addr_to_peer.contains_key(&addr) {
                            let _ = result.send(Ok(()));
                        } else {
                            connect_waiters.entry(addr).or_default().push(result);
                            if dialing.insert(addr)
                                && let Err(error) = swarm.dial(socket_to_multiaddr(addr))
                            {
                                dialing.remove(&addr);
                                let error = error.to_string();
                                fail_connect(&mut connect_waiters, addr, error.clone());
                                fail_queued(&mut queued, addr, error);
                            }
                        }
                    }
                    Command::Request { addr, message, result } => {
                        if let Some(peer) = addr_to_peer.get(&addr).copied() {
                            send_request(&mut swarm, peer, message, result, &mut outstanding);
                        } else {
                            queued.entry(addr).or_default().push(PendingRequest { message, result });
                            if dialing.insert(addr)
                                && let Err(error) = swarm.dial(socket_to_multiaddr(addr))
                            {
                                dialing.remove(&addr);
                                let error = error.to_string();
                                fail_connect(&mut connect_waiters, addr, error.clone());
                                fail_queued(&mut queued, addr, error);
                            }
                        }
                    }
                    Command::Disconnect(addr) => {
                        if let Some(peer) = addr_to_peer.remove(&addr) {
                            peer_to_addr.remove(&peer);
                            let _ = swarm.disconnect_peer_id(peer);
                        }
                    }
                    Command::Shutdown => break,
                }
            }
            event = swarm.select_next_some() => {
                use libp2p::swarm::SwarmEvent;
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        if let Some(addr) = multiaddr_to_socket(endpoint.get_remote_address()) {
                            dialing.remove(&addr);
                            addr_to_peer.insert(addr, peer_id);
                            peer_to_addr.insert(peer_id, addr);
                            if let Ok(mut peers) = peers.lock() {
                                peers.entry(addr).or_insert_with(|| super::PeerState::new(addr));
                            }
                            if let Some(waiters) = connect_waiters.remove(&addr) {
                                for waiter in waiters { let _ = waiter.send(Ok(())); }
                            }
                            if let Some(requests) = queued.remove(&addr) {
                                for request in requests {
                                    send_request(&mut swarm, peer_id, request.message, request.result, &mut outstanding);
                                }
                            }
                            println!("[P2P] libp2p_connected peer_id={peer_id} addr={addr}");
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, num_established, .. } if num_established == 0 => {
                        if let Some(addr) = peer_to_addr.remove(&peer_id) {
                            addr_to_peer.remove(&addr);
                            println!("[P2P] libp2p_disconnected peer_id={peer_id} addr={addr}");
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        let message = error.to_string();
                        let failed_addrs = match &error {
                            libp2p::swarm::DialError::Transport(errors) => errors
                                .iter()
                                .filter_map(|(address, _)| multiaddr_to_socket(address))
                                .collect::<Vec<_>>(),
                            libp2p::swarm::DialError::LocalPeerId { endpoint }
                            | libp2p::swarm::DialError::WrongPeerId { endpoint, .. } => {
                                multiaddr_to_socket(endpoint.get_remote_address())
                                    .into_iter()
                                    .collect()
                            }
                            _ => Vec::new(),
                        };
                        for addr in failed_addrs {
                            dialing.remove(&addr);
                            fail_connect(&mut connect_waiters, addr, message.clone());
                            fail_queued(&mut queued, addr, message.clone());
                        }
                        if let Some(peer_id) = peer_id
                            && let Some(addr) = peer_to_addr.remove(&peer_id)
                        {
                            addr_to_peer.remove(&addr);
                            fail_connect(&mut connect_waiters, addr, message.clone());
                            fail_queued(&mut queued, addr, message);
                        }
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("[P2P] libp2p_listening peer_id={} addr={address}", swarm.local_peer_id());
                    }
                    SwarmEvent::Behaviour(XparqBehaviourEvent::Requests(event)) => {
                        handle_request_event(event, &mut swarm, &node, &peers, &peer_to_addr, &mut outstanding);
                    }
                    SwarmEvent::Behaviour(XparqBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        for address in info.listen_addrs {
                            swarm.behaviour_mut().kad.add_address(&peer_id, address.clone());
                            swarm.add_peer_address(peer_id, address.clone());
                            if let Some(addr) = multiaddr_to_socket(&address) {
                                addr_to_peer.insert(addr, peer_id);
                                peer_to_addr.entry(peer_id).or_insert(addr);
                                if let Ok(mut peers) = peers.lock() {
                                    peers.entry(addr).or_insert_with(|| super::PeerState::new(addr));
                                }
                                if let Some(waiters) = connect_waiters.remove(&addr) {
                                    for waiter in waiters {
                                        let _ = waiter.send(Ok(()));
                                    }
                                }
                                if let Some(requests) = queued.remove(&addr) {
                                    for request in requests {
                                        send_request(
                                            &mut swarm,
                                            peer_id,
                                            request.message,
                                            request.result,
                                            &mut outstanding,
                                        );
                                    }
                                }
                            }
                        }
                        let _ = swarm.behaviour_mut().kad.bootstrap();
                    }
                    SwarmEvent::Behaviour(XparqBehaviourEvent::Kad(kad::Event::RoutingUpdated {
                        peer,
                        addresses,
                        ..
                    })) => {
                        for address in addresses.iter() {
                            swarm.add_peer_address(peer, address.clone());
                            if let Some(addr) = multiaddr_to_socket(address) {
                                addr_to_peer.insert(addr, peer);
                                peer_to_addr.entry(peer).or_insert(addr);
                                if let Ok(mut peers) = peers.lock() {
                                    peers.entry(addr).or_insert_with(|| super::PeerState::new(addr));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn build_swarm(identity_path: &Path) -> Result<Swarm<XparqBehaviour>, String> {
    let identity = load_or_create_identity(identity_path)?;
    SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|error| error.to_string())?
        .with_behaviour(|key| {
            let peer_id = PeerId::from(key.public());
            let requests = request_response::Behaviour::new(
                [(XPARQ_PROTOCOL, ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(REQUEST_TIMEOUT)
                    .with_max_concurrent_streams(256),
            );
            let identify = identify::Behaviour::new(
                identify::Config::new("/xparq/identify/1".to_string(), key.public())
                    .with_interval(Duration::from_secs(30))
                    .with_push_listen_addr_updates(true),
            );
            let kad = kad::Behaviour::new(peer_id, MemoryStore::new(peer_id));
            let ping = ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(15))
                    .with_timeout(Duration::from_secs(20)),
            );
            XparqBehaviour {
                requests,
                identify,
                kad,
                ping,
            }
        })
        .map_err(|error| error.to_string())
        .map(|builder| {
            builder
                .with_swarm_config(|config| {
                    config.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT)
                })
                .build()
        })
}

fn load_or_create_identity(path: &Path) -> Result<libp2p::identity::Keypair, String> {
    match std::fs::read(path) {
        Ok(bytes) => libp2p::identity::Keypair::from_protobuf_encoding(&bytes)
            .map_err(|error| format!("invalid libp2p identity {}: {error}", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    format!("failed to create libp2p identity directory: {error}")
                })?;
            }
            let identity = libp2p::identity::Keypair::generate_ed25519();
            let encoded = identity
                .to_protobuf_encoding()
                .map_err(|error| format!("failed to encode libp2p identity: {error}"))?;
            std::fs::write(path, encoded).map_err(|error| {
                format!(
                    "failed to persist libp2p identity {}: {error}",
                    path.display()
                )
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                    |error| {
                        format!(
                            "failed to protect libp2p identity {}: {error}",
                            path.display()
                        )
                    },
                )?;
            }
            Ok(identity)
        }
        Err(error) => Err(format!(
            "failed to read libp2p identity {}: {error}",
            path.display()
        )),
    }
}

fn send_request(
    swarm: &mut Swarm<XparqBehaviour>,
    peer: PeerId,
    message: NetworkMessage,
    result: std_mpsc::SyncSender<Result<Option<NetworkMessage>, String>>,
    outstanding: &mut HashMap<
        request_response::OutboundRequestId,
        std_mpsc::SyncSender<Result<Option<NetworkMessage>, String>>,
    >,
) {
    let request_id = swarm
        .behaviour_mut()
        .requests
        .send_request(&peer, WireRequest { message });
    outstanding.insert(request_id, result);
}

fn handle_request_event(
    event: request_response::Event<WireRequest, WireResponse>,
    swarm: &mut Swarm<XparqBehaviour>,
    node: &Arc<Mutex<Node>>,
    peers: &Arc<Mutex<HashMap<SocketAddr, super::PeerState>>>,
    peer_to_addr: &HashMap<PeerId, SocketAddr>,
    outstanding: &mut HashMap<
        request_response::OutboundRequestId,
        std_mpsc::SyncSender<Result<Option<NetworkMessage>, String>>,
    >,
) {
    match event {
        request_response::Event::Message { peer, message } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let response = if matches!(request.message, NetworkMessage::GetPeers) {
                    let infos = peers
                        .lock()
                        .map(|peers| {
                            peers
                                .keys()
                                .take(64)
                                .map(|addr| PeerInfo {
                                    address: addr.to_string(),
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    Ok(Some(NetworkMessage::Peers(infos)))
                } else {
                    node.lock()
                        .map_err(|_| "node state lock poisoned".to_string())
                        .and_then(|mut node| {
                            handle_message(&mut node, request.message)
                                .map_err(|error| error.to_string())
                        })
                };
                let response = WireResponse {
                    message: response.unwrap_or_else(|error| {
                        Some(NetworkMessage::Reject {
                            reason: RejectReason::InvalidMessage,
                            message: error,
                        })
                    }),
                };
                if swarm
                    .behaviour_mut()
                    .requests
                    .send_response(channel, response)
                    .is_err()
                {
                    eprintln!("[P2P] libp2p_response_failed peer_id={peer}");
                }
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                if let Some(result) = outstanding.remove(&request_id) {
                    let _ = result.send(Ok(response.message));
                }
            }
        },
        request_response::Event::OutboundFailure {
            peer,
            request_id,
            error,
        } => {
            if let Some(result) = outstanding.remove(&request_id) {
                let addr = peer_to_addr
                    .get(&peer)
                    .map(ToString::to_string)
                    .unwrap_or_else(|| peer.to_string());
                let _ = result.send(Err(format!("libp2p request failed peer={addr}: {error}")));
            }
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            eprintln!("[P2P] libp2p_inbound_failed peer_id={peer} error=\"{error}\"");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

fn fail_connect(
    waiters: &mut HashMap<SocketAddr, Vec<std_mpsc::SyncSender<Result<(), String>>>>,
    addr: SocketAddr,
    error: String,
) {
    if let Some(waiters) = waiters.remove(&addr) {
        for waiter in waiters {
            let _ = waiter.send(Err(error.clone()));
        }
    }
}

fn fail_queued(
    queued: &mut HashMap<SocketAddr, Vec<PendingRequest>>,
    addr: SocketAddr,
    error: String,
) {
    if let Some(requests) = queued.remove(&addr) {
        for request in requests {
            let _ = request.result.send(Err(error.clone()));
        }
    }
}

pub fn socket_to_multiaddr(addr: SocketAddr) -> Multiaddr {
    let mut multiaddr = Multiaddr::empty();
    match addr.ip() {
        IpAddr::V4(ip) => multiaddr.push(libp2p::multiaddr::Protocol::Ip4(ip)),
        IpAddr::V6(ip) => multiaddr.push(libp2p::multiaddr::Protocol::Ip6(ip)),
    }
    multiaddr.push(libp2p::multiaddr::Protocol::Tcp(addr.port()));
    multiaddr
}

pub fn multiaddr_to_socket(addr: &Multiaddr) -> Option<SocketAddr> {
    let mut ip = None;
    let mut port = None;
    for protocol in addr.iter() {
        match protocol {
            libp2p::multiaddr::Protocol::Ip4(value) => ip = Some(IpAddr::V4(value)),
            libp2p::multiaddr::Protocol::Ip6(value) => ip = Some(IpAddr::V6(value)),
            libp2p::multiaddr::Protocol::Tcp(value) => port = Some(value),
            _ => {}
        }
    }
    Some(SocketAddr::new(ip?, port?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_multiaddr_roundtrip_supports_ipv4_and_ipv6() {
        for addr in [
            "127.0.0.1:18181".parse::<SocketAddr>().unwrap(),
            "[::1]:18181".parse::<SocketAddr>().unwrap(),
        ] {
            assert_eq!(multiaddr_to_socket(&socket_to_multiaddr(addr)), Some(addr));
        }
    }

    #[test]
    fn node_identity_is_persistent_and_private() {
        let unique = format!(
            "xparq-libp2p-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        let path = directory.join("identity.key");
        let first = load_or_create_identity(&path).unwrap();
        let second = load_or_create_identity(&path).unwrap();
        assert_eq!(first.public().to_peer_id(), second.public().to_peer_id());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn two_swarms_establish_encrypted_multiplexed_connection() {
        let unique = format!(
            "xparq-libp2p-pair-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        let first_path = directory.join("first.key");
        let second_path = directory.join("second.key");
        let mut first = build_swarm(&first_path).unwrap();
        let mut second = build_swarm(&second_path).unwrap();
        let second_peer = *second.local_peer_id();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            second
                .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .unwrap();
            let listen_addr = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } =
                        second.select_next_some().await
                    {
                        break address;
                    }
                }
            })
            .await
            .expect("second swarm did not start listening");
            first.dial(listen_addr).unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    tokio::select! {
                        event = first.select_next_some() => {
                            if matches!(event, libp2p::swarm::SwarmEvent::ConnectionEstablished { .. }) {
                                break;
                            }
                        }
                        _ = second.select_next_some() => {}
                    }
                }
            })
            .await
            .expect("Noise/Yamux connection was not established");

            let request_id = first.behaviour_mut().requests.send_request(
                &second_peer,
                WireRequest {
                    message: NetworkMessage::Ping { nonce: 42 },
                },
            );
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    tokio::select! {
                        event = second.select_next_some() => {
                            if let libp2p::swarm::SwarmEvent::Behaviour(
                                XparqBehaviourEvent::Requests(request_response::Event::Message {
                                    message: request_response::Message::Request { request, channel, .. },
                                    ..
                                })
                            ) = event {
                                assert!(matches!(request.message, NetworkMessage::Ping { nonce: 42 }));
                                second.behaviour_mut().requests.send_response(
                                    channel,
                                    WireResponse { message: Some(NetworkMessage::Pong { nonce: 42 }) },
                                ).unwrap();
                            }
                        }
                        event = first.select_next_some() => {
                            if let libp2p::swarm::SwarmEvent::Behaviour(
                                XparqBehaviourEvent::Requests(request_response::Event::Message {
                                    message: request_response::Message::Response {
                                        request_id: response_id,
                                        response,
                                    },
                                    ..
                                })
                            ) = event {
                                assert_eq!(response_id, request_id);
                                assert!(matches!(response.message, Some(NetworkMessage::Pong { nonce: 42 })));
                                break;
                            }
                        }
                    }
                }
            })
            .await
            .expect("Borsh request-response did not complete");
        });

        std::fs::remove_file(first_path).unwrap();
        std::fs::remove_file(second_path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
