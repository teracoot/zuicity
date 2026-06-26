//! Juicity wire protocol primitives shared by client, server, and dae adapters.

use base64::{Engine, engine::general_purpose};
use bytes::BufMut;
use sha2::{Digest, Sha256};
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64 as PlatformAtomicU64;
#[cfg(not(target_has_atomic = "64"))]
use std::sync::{Mutex, MutexGuard};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::atomic::Ordering,
};
use uuid::Uuid;

/// A 64-bit counter that remains available on targets without native 64-bit atomics.
#[cfg(target_has_atomic = "64")]
#[derive(Debug)]
pub struct AtomicCounter64(PlatformAtomicU64);

/// A 64-bit counter that remains available on targets without native 64-bit atomics.
#[cfg(not(target_has_atomic = "64"))]
#[derive(Debug)]
pub struct AtomicCounter64(Mutex<u64>);

impl AtomicCounter64 {
    /// Creates a counter with an initial value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        #[cfg(target_has_atomic = "64")]
        {
            Self(PlatformAtomicU64::new(value))
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            Self(Mutex::new(value))
        }
    }

    /// Loads the current counter value.
    #[cfg(target_has_atomic = "64")]
    #[must_use]
    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }

    /// Loads the current counter value.
    #[cfg(not(target_has_atomic = "64"))]
    #[must_use]
    pub fn load(&self, _ordering: Ordering) -> u64 {
        *self.lock_value()
    }

    /// Adds to the counter, returning the previous value.
    #[cfg(target_has_atomic = "64")]
    pub fn fetch_add(&self, value: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(value, ordering)
    }

    /// Adds to the counter, returning the previous value.
    #[cfg(not(target_has_atomic = "64"))]
    pub fn fetch_add(&self, value: u64, _ordering: Ordering) -> u64 {
        let mut guard = self.lock_value();
        let previous = *guard;
        *guard = previous.wrapping_add(value);
        previous
    }

    /// Applies an update closure to the counter, returning the previous value on success.
    #[cfg(target_has_atomic = "64")]
    pub fn fetch_update<F>(
        &self,
        set_order: Ordering,
        fetch_order: Ordering,
        f: F,
    ) -> Result<u64, u64>
    where
        F: FnMut(u64) -> Option<u64>,
    {
        self.0.fetch_update(set_order, fetch_order, f)
    }

    /// Applies an update closure to the counter, returning the previous value on success.
    #[cfg(not(target_has_atomic = "64"))]
    pub fn fetch_update<F>(
        &self,
        _set_order: Ordering,
        _fetch_order: Ordering,
        mut f: F,
    ) -> Result<u64, u64>
    where
        F: FnMut(u64) -> Option<u64>,
    {
        let mut guard = self.lock_value();
        let previous = *guard;
        if let Some(next) = f(previous) {
            *guard = next;
            Ok(previous)
        } else {
            Err(previous)
        }
    }

    #[cfg(not(target_has_atomic = "64"))]
    fn lock_value(&self) -> MutexGuard<'_, u64> {
        match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl Default for AtomicCounter64 {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Juicity protocol version used by upstream Juicity.
pub const VERSION_0: u8 = 0;

/// Authentication command type used on the unidirectional auth stream.
pub const CMD_AUTHENTICATION: u8 = 0;

/// TLS ALPN required by the official Juicity specification.
pub const ALPN_H3: &str = "h3";

/// Authentication token length in bytes.
pub const AUTH_TOKEN_LEN: usize = 32;

/// UUID length in authentication requests.
pub const AUTH_UUID_LEN: usize = 16;

/// Command header length in bytes: version followed by command type.
pub const COMMAND_HEADER_LEN: usize = 2;

/// Juicity authentication request frame length in bytes.
pub const AUTHENTICATION_FRAME_LEN: usize = COMMAND_HEADER_LEN + AUTH_UUID_LEN + AUTH_TOKEN_LEN;

/// TCP proxy network discriminator.
pub const NETWORK_TCP: u8 = 1;

/// UDP proxy network discriminator.
pub const NETWORK_UDP: u8 = 3;

/// IPv4 proxy address discriminator.
pub const ADDR_TYPE_IPV4: u8 = 0;

/// IPv6 proxy address discriminator.
pub const ADDR_TYPE_IPV6: u8 = 1;

/// Domain proxy address discriminator.
pub const ADDR_TYPE_DOMAIN: u8 = 2;

/// Runtime IPv4 metadata discriminator used by upstream outbound's Trojan-compatible codec.
pub const RUNTIME_ADDR_TYPE_IPV4: u8 = 1;

/// Runtime command metadata discriminator used by upstream outbound's Trojan-compatible codec.
pub const RUNTIME_ADDR_TYPE_MSG: u8 = 2;

/// Runtime domain metadata discriminator used by upstream outbound's Trojan-compatible codec.
pub const RUNTIME_ADDR_TYPE_DOMAIN: u8 = 3;

/// Runtime IPv6 metadata discriminator used by upstream outbound's Trojan-compatible codec.
pub const RUNTIME_ADDR_TYPE_IPV6: u8 = 4;

/// UDP-over-stream payload length field width.
pub const UDP_PAYLOAD_LENGTH_LEN: usize = 2;

/// Supported Juicity proxy networks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    /// TCP stream proxying.
    Tcp,
    /// UDP-over-stream proxying.
    Udp,
}

impl Network {
    /// Returns the upstream wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Tcp => NETWORK_TCP,
            Self::Udp => NETWORK_UDP,
        }
    }
}

impl TryFrom<u8> for Network {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            NETWORK_TCP => Ok(Self::Tcp),
            NETWORK_UDP => Ok(Self::Udp),
            other => Err(ProtocolError::UnknownNetwork(other)),
        }
    }
}

/// Supported Juicity proxy address encodings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddrType {
    /// IPv4 address, 4 bytes.
    Ipv4,
    /// IPv6 address, 16 bytes.
    Ipv6,
    /// Domain name, one-byte length followed by bytes.
    Domain,
}

impl AddrType {
    /// Returns the upstream wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Ipv4 => ADDR_TYPE_IPV4,
            Self::Ipv6 => ADDR_TYPE_IPV6,
            Self::Domain => ADDR_TYPE_DOMAIN,
        }
    }
}

impl TryFrom<u8> for AddrType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            ADDR_TYPE_IPV4 => Ok(Self::Ipv4),
            ADDR_TYPE_IPV6 => Ok(Self::Ipv6),
            ADDR_TYPE_DOMAIN => Ok(Self::Domain),
            other => Err(ProtocolError::UnknownAddrType(other)),
        }
    }
}

/// Borrowed destination address encoded in a Juicity proxy header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyAddress<'a> {
    /// IPv4 destination address.
    Ipv4(Ipv4Addr),
    /// IPv6 destination address.
    Ipv6(Ipv6Addr),
    /// Domain destination address bytes.
    Domain(&'a [u8]),
}

impl ProxyAddress<'_> {
    /// Returns the runtime metadata length without the leading network byte.
    #[must_use]
    pub fn runtime_metadata_len(&self) -> usize {
        match self {
            Self::Ipv4(_) => 1 + 4 + 2,
            Self::Ipv6(_) => 1 + 16 + 2,
            Self::Domain(domain) => 1 + 1 + domain.len() + 2,
        }
    }
}

/// Juicity proxy header used when opening stream-carried TCP/UDP requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyHeader<'a> {
    /// Proxied layer-4 network.
    pub network: Network,
    /// Proxied destination address.
    pub address: ProxyAddress<'a>,
    /// Proxied destination port.
    pub port: u16,
}

impl<'a> ProxyHeader<'a> {
    /// Creates a proxy header from network, destination address, and port.
    #[must_use]
    pub const fn new(network: Network, address: ProxyAddress<'a>, port: u16) -> Self {
        Self {
            network,
            address,
            port,
        }
    }

    /// Returns the encoded header length in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        1 + self.address.runtime_metadata_len()
    }

    /// Encodes the runtime proxy header into the supplied buffer.
    pub fn encode_to<B: BufMut>(&self, dst: &mut B) -> Result<(), ProtocolError> {
        dst.put_u8(self.network.as_u8());
        encode_runtime_metadata(self.address, self.port, dst)
    }

    /// Encodes only the runtime target metadata without the leading network byte.
    pub fn encode_target_to<B: BufMut>(&self, dst: &mut B) -> Result<(), ProtocolError> {
        encode_runtime_metadata(self.address, self.port, dst)
    }

    /// Decodes a runtime proxy header, returning the header and remaining bytes.
    pub fn decode(input: &'a [u8]) -> Result<(Self, &'a [u8]), ProtocolError> {
        require_len(input, 2)?;
        let network = Network::try_from(input[0])?;
        let (address, port, consumed) = decode_runtime_metadata(&input[1..])?;
        Ok((Self::new(network, address, port), &input[1 + consumed..]))
    }
}

/// Encodes one upstream Juicity UDP-over-stream packet frame.
pub fn encode_udp_datagram<B: BufMut>(
    header: &ProxyHeader<'_>,
    payload: &[u8],
    dst: &mut B,
) -> Result<(), ProtocolError> {
    let payload_len = payload.len();
    if payload_len > u16::MAX as usize {
        return Err(ProtocolError::UdpPayloadTooLong(payload_len));
    }
    header.encode_target_to(dst)?;
    dst.put_u16(payload_len as u16);
    dst.put_slice(payload);
    Ok(())
}

/// Decodes one upstream Juicity UDP-over-stream packet frame.
pub fn decode_udp_datagram<'a>(
    input: &'a [u8],
) -> Result<(ProxyHeader<'a>, &'a [u8], &'a [u8]), ProtocolError> {
    let (address, port, consumed) = decode_runtime_metadata(input)?;
    let rest = &input[consumed..];
    require_len(rest, UDP_PAYLOAD_LENGTH_LEN)?;
    let payload_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    let frame_len = UDP_PAYLOAD_LENGTH_LEN + payload_len;
    require_len(rest, frame_len)?;
    Ok((
        ProxyHeader::new(Network::Udp, address, port),
        &rest[UDP_PAYLOAD_LENGTH_LEN..frame_len],
        &rest[frame_len..],
    ))
}

fn encode_runtime_metadata<B: BufMut>(
    address: ProxyAddress<'_>,
    port: u16,
    dst: &mut B,
) -> Result<(), ProtocolError> {
    match address {
        ProxyAddress::Ipv4(addr) => {
            dst.put_u8(RUNTIME_ADDR_TYPE_IPV4);
            dst.put_slice(&addr.octets());
        }
        ProxyAddress::Ipv6(addr) => {
            dst.put_u8(RUNTIME_ADDR_TYPE_IPV6);
            dst.put_slice(&addr.octets());
        }
        ProxyAddress::Domain(domain) => {
            let domain_len = domain.len();
            if domain_len > u8::MAX as usize {
                return Err(ProtocolError::DomainTooLong(domain_len));
            }
            dst.put_u8(RUNTIME_ADDR_TYPE_DOMAIN);
            dst.put_u8(domain_len as u8);
            dst.put_slice(domain);
        }
    }
    dst.put_u16(port);
    Ok(())
}

fn decode_runtime_metadata(input: &[u8]) -> Result<(ProxyAddress<'_>, u16, usize), ProtocolError> {
    require_len(input, 1)?;
    match input[0] {
        RUNTIME_ADDR_TYPE_IPV4 => {
            let consumed = 1 + 4 + 2;
            require_len(input, consumed)?;
            let address = Ipv4Addr::new(input[1], input[2], input[3], input[4]);
            let port = u16::from_be_bytes([input[5], input[6]]);
            Ok((ProxyAddress::Ipv4(address), port, consumed))
        }
        RUNTIME_ADDR_TYPE_IPV6 => {
            let consumed = 1 + 16 + 2;
            require_len(input, consumed)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&input[1..17]);
            let port = u16::from_be_bytes([input[17], input[18]]);
            Ok((ProxyAddress::Ipv6(Ipv6Addr::from(octets)), port, consumed))
        }
        RUNTIME_ADDR_TYPE_DOMAIN => {
            require_len(input, 2)?;
            let domain_len = input[1] as usize;
            let consumed = 1 + 1 + domain_len + 2;
            require_len(input, consumed)?;
            let domain_end = 2 + domain_len;
            let port = u16::from_be_bytes([input[domain_end], input[domain_end + 1]]);
            Ok((ProxyAddress::Domain(&input[2..domain_end]), port, consumed))
        }
        other => Err(ProtocolError::UnknownRuntimeAddrType(other)),
    }
}

fn require_len(input: &[u8], needed: usize) -> Result<(), ProtocolError> {
    if input.len() < needed {
        Err(ProtocolError::Truncated {
            needed,
            available: input.len(),
        })
    } else {
        Ok(())
    }
}

/// Juicity authentication request payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationRequest {
    /// Authenticated user UUID.
    pub uuid: Uuid,
    /// TLS exporter token.
    pub token: [u8; AUTH_TOKEN_LEN],
}

impl AuthenticationRequest {
    /// Creates an authentication request from a UUID and TLS exporter token.
    #[must_use]
    pub const fn new(uuid: Uuid, token: [u8; AUTH_TOKEN_LEN]) -> Self {
        Self { uuid, token }
    }

    /// Returns the encoded authentication frame length.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        AUTHENTICATION_FRAME_LEN
    }

    /// Encodes the upstream authentication command frame.
    pub fn encode_to<B: BufMut>(&self, dst: &mut B) {
        dst.put_u8(VERSION_0);
        dst.put_u8(CMD_AUTHENTICATION);
        dst.put_slice(self.uuid.as_bytes());
        dst.put_slice(&self.token);
    }

    /// Decodes one upstream authentication command frame, returning the request and remaining bytes.
    pub fn decode(input: &[u8]) -> Result<(Self, &[u8]), ProtocolError> {
        require_len(input, AUTHENTICATION_FRAME_LEN)?;
        let version = input[0];
        if version != VERSION_0 {
            return Err(ProtocolError::UnexpectedVersion(version));
        }
        let command = input[1];
        if command != CMD_AUTHENTICATION {
            return Err(ProtocolError::UnexpectedCommandType(command));
        }

        let mut uuid = [0u8; AUTH_UUID_LEN];
        uuid.copy_from_slice(&input[COMMAND_HEADER_LEN..COMMAND_HEADER_LEN + AUTH_UUID_LEN]);
        let mut token = [0u8; AUTH_TOKEN_LEN];
        token.copy_from_slice(&input[COMMAND_HEADER_LEN + AUTH_UUID_LEN..AUTHENTICATION_FRAME_LEN]);
        Ok((
            Self::new(Uuid::from_bytes(uuid), token),
            &input[AUTHENTICATION_FRAME_LEN..],
        ))
    }
}

/// Exports the Juicity authentication token using the upstream UUID/password exporter inputs.
#[must_use]
pub fn export_authentication_token(
    uuid: Uuid,
    password: &[u8],
    exporter: impl FnOnce(&mut [u8], &[u8], &[u8]) -> Result<(), ProtocolError>,
) -> Result<[u8; AUTH_TOKEN_LEN], ProtocolError> {
    let mut token = [0u8; AUTH_TOKEN_LEN];
    exporter(&mut token, uuid.as_bytes(), password)?;
    Ok(token)
}

/// Errors emitted by protocol parsing and helpers.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ProtocolError {
    /// Unknown proxy network discriminator.
    #[error("unknown Juicity network value {0}")]
    UnknownNetwork(u8),
    /// Unknown proxy address discriminator.
    #[error("unknown Juicity address type value {0}")]
    UnknownAddrType(u8),
    /// Unknown runtime metadata address discriminator.
    #[error("unknown Juicity runtime address type value {0}")]
    UnknownRuntimeAddrType(u8),
    /// Unexpected command frame version.
    #[error("unexpected Juicity command version {0}")]
    UnexpectedVersion(u8),
    /// Unexpected command type in an authentication frame.
    #[error("unexpected Juicity command type {0}")]
    UnexpectedCommandType(u8),
    /// TLS exporter failed while deriving the authentication token.
    #[error("TLS exporter failed: {0}")]
    Exporter(String),
    /// Domain cannot be represented in the one-byte runtime metadata length field.
    #[error("Juicity domain length {0} exceeds 255 bytes")]
    DomainTooLong(usize),
    /// UDP payload cannot be represented in the two-byte length field.
    #[error("Juicity UDP payload length {0} exceeds 65535 bytes")]
    UdpPayloadTooLong(usize),
    /// Frame ended before the required number of bytes were available.
    #[error("truncated Juicity frame: needed {needed} bytes, available {available}")]
    Truncated {
        /// Required byte count.
        needed: usize,
        /// Available byte count.
        available: usize,
    },
    /// Invalid PEM certificate chain data.
    #[error("invalid PEM certificate chain")]
    InvalidCertificateChainPem,
}

/// Generates the upstream certificate-chain pin hash.
#[must_use]
pub fn generate_cert_chain_hash<'a>(
    raw_certs: impl IntoIterator<Item = &'a [u8]>,
) -> Option<[u8; 32]> {
    let mut chain_hash: Option<[u8; 32]> = None;
    for cert in raw_certs {
        let cert_hash: [u8; 32] = Sha256::digest(cert).into();
        chain_hash = Some(match chain_hash {
            None => cert_hash,
            Some(previous) => {
                let mut hasher = Sha256::new();
                hasher.update(previous);
                hasher.update(cert_hash);
                hasher.finalize().into()
            }
        });
    }
    chain_hash
}

/// Parses a PEM certificate chain and returns the upstream URL-safe base64 hash string.
pub fn generate_cert_chain_hash_base64_from_pem(pem: &[u8]) -> Result<String, ProtocolError> {
    let mut reader = std::io::Cursor::new(pem);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProtocolError::InvalidCertificateChainPem)?;
    let raw_certs: Vec<Vec<u8>> = certs.into_iter().map(|cert| cert.to_vec()).collect();
    let chain_hash = generate_cert_chain_hash(raw_certs.iter().map(Vec::as_slice))
        .ok_or(ProtocolError::InvalidCertificateChainPem)?;
    Ok(general_purpose::URL_SAFE.encode(chain_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_constants_match_official_spec() {
        assert_eq!(VERSION_0, 0);
        assert_eq!(CMD_AUTHENTICATION, 0);
        assert_eq!(ALPN_H3, "h3");
        assert_eq!(Network::Tcp.as_u8(), 1);
        assert_eq!(Network::Udp.as_u8(), 3);
        assert_eq!(AddrType::Ipv4.as_u8(), 0);
        assert_eq!(AddrType::Ipv6.as_u8(), 1);
        assert_eq!(AddrType::Domain.as_u8(), 2);
    }

    #[test]
    fn proxy_header_encodes_runtime_ipv4_metadata() {
        let header = ProxyHeader::new(
            Network::Tcp,
            ProxyAddress::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            8080,
        );
        let mut encoded = bytes::BytesMut::new();
        header.encode_to(&mut encoded).unwrap();
        assert_eq!(
            encoded.as_ref(),
            &[
                NETWORK_TCP,
                RUNTIME_ADDR_TYPE_IPV4,
                127,
                0,
                0,
                1,
                0x1f,
                0x90
            ]
        );

        let (decoded, rest) = ProxyHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(rest, b"");
    }

    #[test]
    fn proxy_header_encodes_runtime_ipv6_metadata() {
        let addr = std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let header = ProxyHeader::new(Network::Tcp, ProxyAddress::Ipv6(addr), 443);
        let mut encoded = bytes::BytesMut::new();
        header.encode_to(&mut encoded).unwrap();

        let mut expected = Vec::from([NETWORK_TCP, RUNTIME_ADDR_TYPE_IPV6]);
        expected.extend_from_slice(&addr.octets());
        expected.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(encoded.as_ref(), expected.as_slice());

        let (decoded, rest) = ProxyHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(rest, b"");
    }

    #[test]
    fn proxy_header_encodes_runtime_domain_metadata_without_allocating_on_decode() {
        let header = ProxyHeader::new(Network::Udp, ProxyAddress::Domain(b"example.com"), 53);
        let mut encoded = bytes::BytesMut::new();
        header.encode_to(&mut encoded).unwrap();
        assert_eq!(encoded.as_ref(), b"\x03\x03\x0bexample.com\x00\x35");

        let mut with_tail = encoded.to_vec();
        with_tail.extend_from_slice(b"tail");
        let (decoded, rest) = ProxyHeader::decode(&with_tail).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(rest, b"tail");
    }

    #[test]
    fn proxy_header_rejects_domains_longer_than_one_wire_byte() {
        let domain = [b'a'; 256];
        let header = ProxyHeader::new(Network::Tcp, ProxyAddress::Domain(&domain), 443);
        let mut encoded = bytes::BytesMut::new();
        assert_eq!(
            header.encode_to(&mut encoded),
            Err(ProtocolError::DomainTooLong(256))
        );
    }

    #[test]
    fn udp_datagram_codec_matches_upstream_packet_conn_frame() {
        let header = ProxyHeader::new(Network::Udp, ProxyAddress::Domain(b"example.com"), 53);
        let mut encoded = bytes::BytesMut::new();
        encode_udp_datagram(&header, b"dns", &mut encoded).unwrap();
        assert_eq!(encoded.as_ref(), b"\x03\x0bexample.com\x00\x35\x00\x03dns");

        let (decoded_header, payload, rest) = decode_udp_datagram(&encoded).unwrap();
        assert_eq!(decoded_header, header);
        assert_eq!(payload, b"dns");
        assert_eq!(rest, b"");
    }

    #[test]
    fn authentication_request_encodes_upstream_command_frame() {
        let uuid = Uuid::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);
        let mut token = [0u8; AUTH_TOKEN_LEN];
        for (i, byte) in token.iter_mut().enumerate() {
            *byte = 0xa0 + i as u8;
        }
        let request = AuthenticationRequest::new(uuid, token);
        let mut encoded = bytes::BytesMut::new();
        request.encode_to(&mut encoded);

        assert_eq!(AUTHENTICATION_FRAME_LEN, 50);
        assert_eq!(
            hex::encode(encoded.as_ref()),
            "0000000102030405060708090a0b0c0d0e0fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        );

        let (decoded, rest) = AuthenticationRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(rest, b"");
    }

    #[test]
    fn authentication_request_decode_rejects_wrong_command_and_truncation() {
        let mut wrong_command = [0u8; AUTHENTICATION_FRAME_LEN];
        wrong_command[1] = 1;
        assert_eq!(
            AuthenticationRequest::decode(&wrong_command),
            Err(ProtocolError::UnexpectedCommandType(1))
        );

        assert_eq!(
            AuthenticationRequest::decode(&[VERSION_0, CMD_AUTHENTICATION]),
            Err(ProtocolError::Truncated {
                needed: AUTHENTICATION_FRAME_LEN,
                available: 2,
            })
        );
    }

    #[test]
    fn authentication_token_helper_uses_upstream_exporter_label_and_context() {
        let uuid = Uuid::from_bytes([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ]);
        let password = "passw0rd";
        let token =
            export_authentication_token(uuid, password.as_bytes(), |output, label, context| {
                assert_eq!(label, uuid.as_bytes());
                assert_eq!(context, password.as_bytes());
                assert_eq!(output.len(), AUTH_TOKEN_LEN);
                for (i, byte) in output.iter_mut().enumerate() {
                    *byte = 0x40 + i as u8;
                }
                Ok::<(), ProtocolError>(())
            })
            .unwrap();

        assert_eq!(token[0], 0x40);
        assert_eq!(token[31], 0x5f);
    }

    #[test]
    fn authentication_token_helper_propagates_exporter_errors() {
        let uuid = Uuid::nil();
        let result = export_authentication_token(uuid, b"password", |_output, _label, _context| {
            Err(ProtocolError::Exporter("failed".to_string()))
        });

        assert_eq!(result, Err(ProtocolError::Exporter("failed".to_string())));
    }

    #[test]
    fn certificate_chain_hash_matches_upstream_iterative_algorithm() {
        let hash = generate_cert_chain_hash([b"abc".as_slice(), b"def".as_slice()]).unwrap();
        let first: [u8; 32] = Sha256::digest(b"abc").into();
        let second: [u8; 32] = Sha256::digest(b"def").into();
        let expected: [u8; 32] =
            Sha256::digest([first.as_slice(), second.as_slice()].concat()).into();
        assert_eq!(hash, expected);
    }

    #[test]
    fn certificate_chain_hash_from_pem_matches_upstream_cli_fixture() {
        let pem = include_bytes!("../tests/fixtures/certchain.pem");
        let encoded = generate_cert_chain_hash_base64_from_pem(pem).unwrap();
        assert_eq!(encoded, "51IrbkfPN5VRLzlM9q6tPEHhyEckeXrDAzxdmDaQW_0=");
    }

    #[test]
    fn proxy_header_roundtrips_empty_domain() {
        let header = ProxyHeader::new(Network::Tcp, ProxyAddress::Domain(b""), 80);
        let mut encoded = bytes::BytesMut::new();
        header.encode_to(&mut encoded).unwrap();
        assert_eq!(encoded.as_ref(), b"\x01\x03\x00\x00\x50");
        let (decoded, rest) = ProxyHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, header);
        assert!(rest.is_empty());
    }

    #[test]
    fn proxy_header_roundtrips_max_length_domain() {
        let domain = [b'a'; 255];
        let header = ProxyHeader::new(Network::Tcp, ProxyAddress::Domain(&domain), 443);
        let mut encoded = bytes::BytesMut::new();
        header.encode_to(&mut encoded).unwrap();
        assert_eq!(encoded[1], RUNTIME_ADDR_TYPE_DOMAIN);
        assert_eq!(encoded[2], 255);
        let (decoded, rest) = ProxyHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, header);
        assert!(rest.is_empty());
    }

    #[test]
    fn proxy_header_roundtrips_port_zero_and_max() {
        for port in [0_u16, u16::MAX] {
            let header = ProxyHeader::new(
                Network::Udp,
                ProxyAddress::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
                port,
            );
            let mut encoded = bytes::BytesMut::new();
            header.encode_to(&mut encoded).unwrap();
            let (decoded, _) = ProxyHeader::decode(&encoded).unwrap();
            assert_eq!(decoded.port, port);
        }
    }

    #[test]
    fn proxy_header_decode_rejects_unknown_address_type() {
        assert!(matches!(
            ProxyHeader::decode(&[0x01, 0x7f, 0x00, 0x00]),
            Err(ProtocolError::UnknownRuntimeAddrType(0x7f))
        ));
    }

    #[test]
    fn proxy_header_decode_rejects_domain_length_overrun() {
        let truncated = [0x01, RUNTIME_ADDR_TYPE_DOMAIN, 0x10, b'a', b'b'];
        assert!(matches!(
            ProxyHeader::decode(&truncated),
            Err(ProtocolError::Truncated { .. })
        ));
    }

    #[test]
    fn proxy_header_roundtrips_ipv6() {
        let header = ProxyHeader::new(
            Network::Tcp,
            ProxyAddress::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            8443,
        );
        let mut encoded = bytes::BytesMut::new();
        header.encode_to(&mut encoded).unwrap();
        let (decoded, rest) = ProxyHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, header);
        assert!(rest.is_empty());
    }
}
