//! Ethernet/VLAN IPv4/IPv6 UDP decoding; fragments are not reassembled.
use crate::models::Endpoint;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct Datagram<'a> {
    pub source: Endpoint,
    pub destination: Endpoint,
    pub payload: &'a [u8],
}
fn word(b: &[u8], n: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(n..n + 2)?.try_into().ok()?))
}
pub fn decode_ethernet(bytes: &[u8]) -> Option<Datagram<'_>> {
    let mut kind = word(bytes, 12)?;
    let mut offset = 14;
    while matches!(kind, 0x8100 | 0x88a8) {
        kind = word(bytes, offset + 2)?;
        offset += 4;
    }
    let ip = bytes.get(offset..)?;
    let (source, destination, udp) = match kind {
        0x0800 => {
            if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != 17 {
                return None;
            }
            let header = (ip[0] as usize & 15) * 4;
            let length = word(ip, 2)? as usize;
            if header < 20 || length < header || word(ip, 6)? & 0x3fff != 0 {
                return None;
            }
            (
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&ip[12..16]).ok()?)),
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&ip[16..20]).ok()?)),
                ip.get(header..length)?,
            )
        }
        0x86dd => {
            if ip.len() < 40 || ip[0] >> 4 != 6 {
                return None;
            }
            let ip = ip.get(..40 + word(ip, 4)? as usize)?;
            let mut next = ip[6];
            let mut cursor = 40;
            for _ in 0..8 {
                if next == 17 {
                    break;
                }
                let size = match next {
                    0 | 43 | 60 => (*ip.get(cursor + 1)? as usize + 1) * 8,
                    _ => return None,
                };
                next = *ip.get(cursor)?;
                cursor += size;
            }
            if next != 17 {
                return None;
            }
            (
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?)),
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).ok()?)),
                ip.get(cursor..)?,
            )
        }
        _ => return None,
    };
    let length = word(udp, 4)? as usize;
    if length < 8 {
        return None;
    }
    Some(Datagram {
        source: Endpoint {
            address: source,
            port: word(udp, 0)?,
        },
        destination: Endpoint {
            address: destination,
            port: word(udp, 2)?,
        },
        payload: udp.get(8..length)?,
    })
}
/// Validate modern STUN framing, including unknown methods, without authentication.
pub fn is_stun(p: &[u8]) -> bool {
    if p.len() < 20 || p[0] & 0xc0 != 0 || p[4..8] != [0x21, 0x12, 0xa4, 0x42] {
        return false;
    }
    let length = u16::from_be_bytes([p[2], p[3]]) as usize;
    if length % 4 != 0 || length + 20 != p.len() {
        return false;
    }
    let mut cursor = 20;
    while cursor < p.len() {
        let Some(length) = word(p, cursor + 2) else {
            return false;
        };
        cursor += 4 + (length as usize + 3) / 4 * 4;
        if cursor > p.len() {
            return false;
        }
    }
    cursor == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stun_rejects_bad_lengths_and_attributes() {
        let mut p = vec![0; 20];
        p[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        assert!(is_stun(&p));
        p[3] = 4;
        assert!(!is_stun(&p));
        p.extend_from_slice(&[0, 1, 0, 8]);
        assert!(!is_stun(&p));
    }
    #[test]
    fn truncated_frames_do_not_panic() {
        for length in 0..100 {
            assert!(decode_ethernet(&vec![0; length]).is_none());
        }
    }

    #[test]
    fn decodes_ipv4_and_ipv6_and_rejects_truncation_and_fragments() {
        for v6 in [false, true] {
            let header = if v6 { 40 } else { 20 };
            let mut frame = vec![0; 14 + header + 12];
            frame[12..14].copy_from_slice(&(if v6 { 0x86ddu16 } else { 0x0800u16 }).to_be_bytes());
            let ip = &mut frame[14..];
            if v6 {
                ip[0] = 0x60;
                ip[4..6].copy_from_slice(&12u16.to_be_bytes());
                ip[6] = 17;
                ip[23] = 1;
                ip[39] = 2;
            } else {
                ip[0] = 0x45;
                ip[2..4].copy_from_slice(&32u16.to_be_bytes());
                ip[9] = 17;
                ip[12..16].copy_from_slice(&[192, 168, 1, 1]);
                ip[16..20].copy_from_slice(&[192, 168, 1, 2]);
            }
            ip[header..header + 2].copy_from_slice(&9000u16.to_be_bytes());
            ip[header + 2..header + 4].copy_from_slice(&9001u16.to_be_bytes());
            ip[header + 4..header + 6].copy_from_slice(&12u16.to_be_bytes());
            let decoded = decode_ethernet(&frame).unwrap();
            assert_eq!(decoded.source.port, 9000);
            assert_eq!(decoded.destination.port, 9001);
            assert_eq!(decoded.source.address.is_ipv6(), v6);
            assert_eq!(decoded.payload.len(), 4);
            assert!(decode_ethernet(&frame[..frame.len() - 1]).is_none());
            if !v6 {
                frame[20] = 0x20;
                assert!(decode_ethernet(&frame).is_none());
            }
        }
    }
}
