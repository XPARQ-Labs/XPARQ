use igd_next::{PortMappingProtocol, search_gateway};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

const NAT_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone)]
pub struct NatMapping {
    pub public_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub lease: Duration,
}

pub fn map_tcp_listener(local_addr: SocketAddr, lease: Duration) -> Result<NatMapping, String> {
    if !local_addr.ip().is_ipv4() {
        return Err("NAT traversal only supports IPv4 listener addresses".to_string());
    }
    let local_ip = local_mapping_ip(local_addr)?;
    let local_addr = SocketAddr::new(IpAddr::V4(local_ip), local_addr.port());
    let lease_secs = lease.as_secs().clamp(60, u32::MAX as u64) as u32;
    let mut errors = Vec::new();
    match map_upnp(local_addr, lease_secs) {
        Ok(mapping) => return Ok(mapping),
        Err(error) => errors.push(error),
    }
    match map_nat_pmp(local_addr, lease_secs) {
        Ok(mapping) => return Ok(mapping),
        Err(error) => errors.push(error),
    }
    match map_pcp(local_addr, lease_secs) {
        Ok(mapping) => return Ok(mapping),
        Err(error) => errors.push(error),
    }
    Err(errors.join("; "))
}

fn map_upnp(local_addr: SocketAddr, lease_secs: u32) -> Result<NatMapping, String> {
    let gateway = search_gateway(Default::default())
        .map_err(|error| format!("UPnP gateway discovery failed: {error}"))?;
    let external_ip = gateway
        .get_external_ip()
        .map_err(|error| format!("UPnP external IP lookup failed: {error}"))?;
    gateway
        .add_port(
            PortMappingProtocol::TCP,
            local_addr.port(),
            local_addr,
            lease_secs,
            "xparq P2P",
        )
        .map_err(|error| format!("UPnP TCP port mapping failed: {error}"))?;
    Ok(NatMapping {
        public_addr: SocketAddr::new(external_ip, local_addr.port()),
        local_addr,
        lease: Duration::from_secs(lease_secs as u64),
    })
}

fn map_nat_pmp(local_addr: SocketAddr, lease_secs: u32) -> Result<NatMapping, String> {
    let gateway = default_gateway_ipv4()?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|error| format!("NAT-PMP socket bind failed: {error}"))?;
    socket
        .set_read_timeout(Some(NAT_DISCOVERY_TIMEOUT))
        .map_err(|error| format!("NAT-PMP read timeout setup failed: {error}"))?;
    socket
        .set_write_timeout(Some(NAT_DISCOVERY_TIMEOUT))
        .map_err(|error| format!("NAT-PMP write timeout setup failed: {error}"))?;
    let gateway_addr = SocketAddr::new(IpAddr::V4(gateway), 5351);

    socket
        .send_to(&[0, 0], gateway_addr)
        .map_err(|error| format!("NAT-PMP external address request failed: {error}"))?;
    let mut response = [0_u8; 32];
    let (len, _) = socket
        .recv_from(&mut response)
        .map_err(|error| format!("NAT-PMP external address response failed: {error}"))?;
    if len < 12
        || response[0] != 0
        || response[1] != 128
        || u16::from_be_bytes([response[2], response[3]]) != 0
    {
        return Err("NAT-PMP external address response was invalid".to_string());
    }
    let external_ip = Ipv4Addr::new(response[8], response[9], response[10], response[11]);

    let mut request = [0_u8; 12];
    request[1] = 2;
    request[4..6].copy_from_slice(&local_addr.port().to_be_bytes());
    request[6..8].copy_from_slice(&local_addr.port().to_be_bytes());
    request[8..12].copy_from_slice(&lease_secs.to_be_bytes());
    socket
        .send_to(&request, gateway_addr)
        .map_err(|error| format!("NAT-PMP TCP mapping request failed: {error}"))?;
    let (len, _) = socket
        .recv_from(&mut response)
        .map_err(|error| format!("NAT-PMP TCP mapping response failed: {error}"))?;
    if len < 16
        || response[0] != 0
        || response[1] != 130
        || u16::from_be_bytes([response[2], response[3]]) != 0
    {
        return Err("NAT-PMP TCP mapping response was invalid".to_string());
    }
    let external_port = u16::from_be_bytes([response[10], response[11]]);
    let mapped_lease = u32::from_be_bytes([response[12], response[13], response[14], response[15]]);
    Ok(NatMapping {
        public_addr: SocketAddr::new(IpAddr::V4(external_ip), external_port),
        local_addr,
        lease: Duration::from_secs(mapped_lease as u64),
    })
}

fn map_pcp(local_addr: SocketAddr, lease_secs: u32) -> Result<NatMapping, String> {
    let gateway = default_gateway_ipv4()?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|error| format!("PCP socket bind failed: {error}"))?;
    socket
        .set_read_timeout(Some(NAT_DISCOVERY_TIMEOUT))
        .map_err(|error| format!("PCP read timeout setup failed: {error}"))?;
    socket
        .set_write_timeout(Some(NAT_DISCOVERY_TIMEOUT))
        .map_err(|error| format!("PCP write timeout setup failed: {error}"))?;

    let mut request = [0_u8; 60];
    request[0] = 2;
    request[1] = 1;
    request[4..8].copy_from_slice(&lease_secs.to_be_bytes());
    request[8..24].copy_from_slice(&ipv4_mapped_ipv6(local_addr.ip()));
    request[24..36].copy_from_slice(b"xparq-NATMAP");
    request[36] = 6;
    request[40..42].copy_from_slice(&local_addr.port().to_be_bytes());
    request[42..44].copy_from_slice(&local_addr.port().to_be_bytes());
    let gateway_addr = SocketAddr::new(IpAddr::V4(gateway), 5351);
    socket
        .send_to(&request, gateway_addr)
        .map_err(|error| format!("PCP MAP request failed: {error}"))?;
    let mut response = [0_u8; 96];
    let (len, _) = socket
        .recv_from(&mut response)
        .map_err(|error| format!("PCP MAP response failed: {error}"))?;
    if len < 60 || response[0] != 2 || response[1] != 129 || response[3] != 0 {
        return Err("PCP MAP response was invalid".to_string());
    }
    let mapped_lease = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
    let external_port = u16::from_be_bytes([response[42], response[43]]);
    let external_ip = ipv4_from_mapped(&response[44..60])
        .ok_or_else(|| "PCP MAP response did not contain an IPv4 address".to_string())?;
    Ok(NatMapping {
        public_addr: SocketAddr::new(IpAddr::V4(external_ip), external_port),
        local_addr,
        lease: Duration::from_secs(mapped_lease as u64),
    })
}

fn local_mapping_ip(local_addr: SocketAddr) -> Result<Ipv4Addr, String> {
    match local_addr.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() => Ok(ip),
        IpAddr::V4(_) => local_ipv4(),
        IpAddr::V6(_) => Err("IPv6 listener cannot be mapped through NAT traversal".to_string()),
    }
}

fn default_gateway_ipv4() -> Result<Ipv4Addr, String> {
    let routes = std::fs::read_to_string("/proc/net/route")
        .map_err(|error| format!("failed to read IPv4 route table: {error}"))?;
    for line in routes.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 3 || fields[1] != "00000000" {
            continue;
        }
        let raw = u32::from_str_radix(fields[2], 16)
            .map_err(|error| format!("invalid default gateway route: {error}"))?;
        let bytes = raw.to_le_bytes();
        return Ok(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]));
    }
    Err("no IPv4 default gateway found".to_string())
}

fn ipv4_mapped_ipv6(ip: IpAddr) -> [u8; 16] {
    let IpAddr::V4(ip) = ip else {
        return [0; 16];
    };
    let octets = ip.octets();
    let mut mapped = [0_u8; 16];
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12..16].copy_from_slice(&octets);
    mapped
}

fn ipv4_from_mapped(bytes: &[u8]) -> Option<Ipv4Addr> {
    if bytes.len() != 16 || bytes[..10] != [0; 10] || bytes[10] != 0xff || bytes[11] != 0xff {
        return None;
    }
    Some(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
}

fn local_ipv4() -> Result<Ipv4Addr, String> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|error| format!("failed to open local UDP probe socket: {error}"))?;
    socket
        .connect((Ipv4Addr::new(8, 8, 8, 8), 80))
        .map_err(|error| format!("failed to detect local IPv4 address: {error}"))?;
    match socket
        .local_addr()
        .map_err(|error| format!("failed to read local IPv4 address: {error}"))?
        .ip()
    {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err("local address probe returned IPv6".to_string()),
    }
}
