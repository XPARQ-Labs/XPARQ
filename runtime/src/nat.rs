use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    time::Duration,
};

use igd_next::{PortMappingProtocol, search_gateway};

const NAT_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug)]
pub struct NatMapping {
    pub public_addr: SocketAddr,
    pub lease: Duration,
}

pub fn map_tcp_listener(listener: SocketAddr, lease: Duration) -> Result<NatMapping, String> {
    if !listener.ip().is_ipv4() {
        return Err("NAT traversal currently supports IPv4 listeners only".into());
    }
    let local_ip = match listener.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() => ip,
        IpAddr::V4(_) => local_ipv4()?,
        IpAddr::V6(_) => return Err("NAT traversal requires an IPv4 listener".into()),
    };
    let local_addr = SocketAddr::new(IpAddr::V4(local_ip), listener.port());
    let lease_seconds = lease.as_secs().clamp(60, u32::MAX as u64) as u32;
    let mut errors = Vec::new();
    match map_upnp(local_addr, listener.port(), lease_seconds) {
        Ok(mapping) => return Ok(mapping),
        Err(error) => errors.push(error),
    }
    match map_nat_pmp(local_addr, lease_seconds) {
        Ok(mapping) => return Ok(mapping),
        Err(error) => errors.push(error),
    }
    match map_pcp(local_addr, lease_seconds) {
        Ok(mapping) => return Ok(mapping),
        Err(error) => errors.push(error),
    }
    Err(errors.join("; "))
}

fn map_upnp(
    local_addr: SocketAddr,
    external_port: u16,
    lease_seconds: u32,
) -> Result<NatMapping, String> {
    let gateway = search_gateway(Default::default())
        .map_err(|error| format!("UPnP gateway discovery failed: {error}"))?;
    let external_ip = gateway
        .get_external_ip()
        .map_err(|error| format!("UPnP external IP lookup failed: {error}"))?;
    gateway
        .add_port(
            PortMappingProtocol::TCP,
            external_port,
            local_addr,
            lease_seconds,
            "XPARQ P2P",
        )
        .map_err(|error| format!("UPnP TCP port mapping failed: {error}"))?;
    Ok(NatMapping {
        public_addr: SocketAddr::new(external_ip, external_port),
        lease: Duration::from_secs(lease_seconds as u64),
    })
}

fn map_nat_pmp(local_addr: SocketAddr, lease_seconds: u32) -> Result<NatMapping, String> {
    let gateway = default_gateway_ipv4()?;
    let socket = nat_socket()?;
    let gateway_addr = SocketAddr::new(IpAddr::V4(gateway), 5351);
    socket
        .send_to(&[0, 0], gateway_addr)
        .map_err(|error| format!("NAT-PMP external address request failed: {error}"))?;
    let mut response = [0_u8; 32];
    let (length, source) = socket
        .recv_from(&mut response)
        .map_err(|error| format!("NAT-PMP external address response failed: {error}"))?;
    if source != gateway_addr
        || length < 12
        || response[0] != 0
        || response[1] != 128
        || u16::from_be_bytes([response[2], response[3]]) != 0
    {
        return Err("NAT-PMP external address response was invalid".into());
    }
    let external_ip = Ipv4Addr::new(response[8], response[9], response[10], response[11]);
    let mut request = [0_u8; 12];
    request[1] = 2;
    request[4..6].copy_from_slice(&local_addr.port().to_be_bytes());
    request[6..8].copy_from_slice(&local_addr.port().to_be_bytes());
    request[8..12].copy_from_slice(&lease_seconds.to_be_bytes());
    socket
        .send_to(&request, gateway_addr)
        .map_err(|error| format!("NAT-PMP TCP mapping request failed: {error}"))?;
    let (length, source) = socket
        .recv_from(&mut response)
        .map_err(|error| format!("NAT-PMP TCP mapping response failed: {error}"))?;
    if source != gateway_addr
        || length < 16
        || response[0] != 0
        || response[1] != 130
        || u16::from_be_bytes([response[2], response[3]]) != 0
    {
        return Err("NAT-PMP TCP mapping response was invalid".into());
    }
    let external_port = u16::from_be_bytes([response[10], response[11]]);
    let mapped_lease = u32::from_be_bytes([response[12], response[13], response[14], response[15]]);
    Ok(NatMapping {
        public_addr: SocketAddr::new(IpAddr::V4(external_ip), external_port),
        lease: Duration::from_secs(mapped_lease as u64),
    })
}

fn map_pcp(local_addr: SocketAddr, lease_seconds: u32) -> Result<NatMapping, String> {
    let gateway = default_gateway_ipv4()?;
    let socket = nat_socket()?;
    let mut request = [0_u8; 60];
    request[0] = 2;
    request[1] = 1;
    request[4..8].copy_from_slice(&lease_seconds.to_be_bytes());
    request[8..24].copy_from_slice(&ipv4_mapped_ipv6(local_addr.ip()));
    getrandom::fill(&mut request[24..36])
        .map_err(|error| format!("generate PCP mapping nonce: {error}"))?;
    request[36] = 6;
    request[40..42].copy_from_slice(&local_addr.port().to_be_bytes());
    request[42..44].copy_from_slice(&local_addr.port().to_be_bytes());
    let gateway_addr = SocketAddr::new(IpAddr::V4(gateway), 5351);
    socket
        .send_to(&request, gateway_addr)
        .map_err(|error| format!("PCP MAP request failed: {error}"))?;
    let mut response = [0_u8; 96];
    let (length, source) = socket
        .recv_from(&mut response)
        .map_err(|error| format!("PCP MAP response failed: {error}"))?;
    if source != gateway_addr
        || length < 60
        || response[0] != 2
        || response[1] != 129
        || response[3] != 0
        || response[24..36] != request[24..36]
        || response[36] != 6
        || response[40..42] != request[40..42]
    {
        return Err("PCP MAP response was invalid".into());
    }
    let mapped_lease = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
    let external_port = u16::from_be_bytes([response[42], response[43]]);
    let external_ip = ipv4_from_mapped(&response[44..60])
        .ok_or("PCP MAP response did not contain an IPv4 address")?;
    Ok(NatMapping {
        public_addr: SocketAddr::new(IpAddr::V4(external_ip), external_port),
        lease: Duration::from_secs(mapped_lease as u64),
    })
}

fn nat_socket() -> Result<UdpSocket, String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|error| format!("NAT traversal socket bind failed: {error}"))?;
    socket
        .set_read_timeout(Some(NAT_DISCOVERY_TIMEOUT))
        .and_then(|_| socket.set_write_timeout(Some(NAT_DISCOVERY_TIMEOUT)))
        .map_err(|error| format!("NAT traversal timeout setup failed: {error}"))?;
    Ok(socket)
}

fn default_gateway_ipv4() -> Result<Ipv4Addr, String> {
    let routes = std::fs::read_to_string("/proc/net/route")
        .map_err(|error| format!("read IPv4 route table: {error}"))?;
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
    Err("no IPv4 default gateway found".into())
}

fn ipv4_mapped_ipv6(ip: IpAddr) -> [u8; 16] {
    let IpAddr::V4(ip) = ip else {
        return [0; 16];
    };
    let mut mapped = [0_u8; 16];
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12..].copy_from_slice(&ip.octets());
    mapped
}

fn ipv4_from_mapped(bytes: &[u8]) -> Option<Ipv4Addr> {
    if bytes.len() != 16 || bytes[..10] != [0; 10] || bytes[10] != 0xff || bytes[11] != 0xff {
        return None;
    }
    Some(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
}

fn local_ipv4() -> Result<Ipv4Addr, String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|error| format!("open local address probe: {error}"))?;
    socket
        .connect((Ipv4Addr::new(8, 8, 8, 8), 80))
        .map_err(|error| format!("detect local IPv4 address: {error}"))?;
    match socket
        .local_addr()
        .map_err(|error| format!("read local IPv4 address: {error}"))?
        .ip()
    {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err("local address probe returned IPv6".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcp_ipv4_mapping_round_trips() {
        let address = Ipv4Addr::new(203, 0, 113, 9);
        let mapped = ipv4_mapped_ipv6(IpAddr::V4(address));
        assert_eq!(ipv4_from_mapped(&mapped), Some(address));
    }

    #[test]
    fn pcp_rejects_non_mapped_ipv6_bytes() {
        assert_eq!(ipv4_from_mapped(&[0; 16]), None);
    }
}
