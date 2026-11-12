use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// An observed endpoint, not necessarily a call participant (it may be a relay).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}

/// Candidate activity window. Duration is an observed traffic interval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSession {
    pub id: String,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub observed_endpoints: Vec<Endpoint>,
    pub caller: Option<Endpoint>,
    pub receiver: Option<Endpoint>,
    pub packet_count: u64,
    pub captured_bytes: u64,
    pub evidence: Vec<String>,
}
