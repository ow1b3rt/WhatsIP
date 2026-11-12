//! Experimental UDP/STUN candidates, not verified WhatsApp calls.
pub mod lifecycle;
#[cfg(test)]
mod tests;
use crate::{
    models::Endpoint,
    packet::{is_stun, Datagram},
};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct Flow {
    pub last_setup_seconds: Option<f64>,
    pub endpoint_a: Endpoint,
    pub endpoint_b: Endpoint,
    pub first_seen_seconds: f64,
    pub last_seen_seconds: f64,
    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub frame_bytes: u64,
    pub stun_packets: u64,
    pub opaque_packets: u64,
    pub candidate_intervals: Vec<CandidateInterval>,
}
#[derive(Debug, Clone, Serialize)]
pub struct CandidateInterval {
    pub start_seconds: f64,
    pub end_seconds: f64,
    pub duration_seconds: f64,
    pub packets: u64,
    pub evidence: Vec<String>,
}
#[derive(Clone)]
struct Activity {
    first: f64,
    last: f64,
    forward: u64,
    reverse: u64,
}
#[derive(Clone)]
struct Tracked {
    flow: Flow,
    activity: Vec<Activity>,
}
#[derive(Default, Clone)]
pub struct Analyzer {
    flows: BTreeMap<(Endpoint, Endpoint), Tracked>,
}
impl Analyzer {
    pub fn snapshot(&self) -> Vec<Flow> {
        self.clone().finish()
    }

    /// Live retention: evict flows idle for two minutes and cap interval history.
    pub fn prune_live(&mut self, now: f64) {
        self.flows
            .retain(|_, tracked| now - tracked.flow.last_seen_seconds < 120.0);
        for tracked in self.flows.values_mut() {
            let excess = tracked.activity.len().saturating_sub(64);
            tracked.activity.drain(..excess);
        }
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
    pub fn observe(&mut self, time: f64, frame_bytes: usize, packet: Datagram<'_>) {
        let forward = packet.source <= packet.destination;
        let key = if forward {
            (packet.source, packet.destination)
        } else {
            (packet.destination, packet.source)
        };
        let tracked = self.flows.entry(key.clone()).or_insert_with(|| Tracked {
            flow: Flow {
                last_setup_seconds: None,
                endpoint_a: key.0,
                endpoint_b: key.1,
                first_seen_seconds: time,
                last_seen_seconds: time,
                packets_a_to_b: 0,
                packets_b_to_a: 0,
                frame_bytes: 0,
                stun_packets: 0,
                opaque_packets: 0,
                candidate_intervals: vec![],
            },
            activity: vec![],
        });
        let flow = &mut tracked.flow;
        flow.last_seen_seconds = time;
        flow.frame_bytes += frame_bytes as u64;
        if forward {
            flow.packets_a_to_b += 1;
        } else {
            flow.packets_b_to_a += 1;
        }
        if is_stun(packet.payload) {
            flow.stun_packets += 1;
            if packet.payload[..2] == [0, 3] {
                flow.last_setup_seconds = Some(time);
            }
            return;
        }
        flow.opaque_packets += 1;
        if packet.payload.is_empty() {
            return;
        }
        if tracked.activity.last().is_none_or(|a| time - a.last > 3.0) {
            tracked.activity.push(Activity {
                first: time,
                last: time,
                forward: 0,
                reverse: 0,
            });
        }
        let a = tracked.activity.last_mut().unwrap();
        a.last = time;
        if forward {
            a.forward += 1;
        } else {
            a.reverse += 1;
        }
    }
    pub fn finish(self) -> Vec<Flow> {
        let mut flows: Vec<_> = self.flows.into_values().map(|mut tracked| {
            if tracked.flow.stun_packets >= 2 {
                tracked.flow.candidate_intervals = tracked.activity.into_iter().filter(|a|
                    a.last - a.first >= 2.0 && a.forward >= 5 && a.reverse >= 5 && a.forward + a.reverse >= 20
                ).map(|a| CandidateInterval {
                    start_seconds: a.first, end_seconds: a.last, duration_seconds: a.last - a.first, packets: a.forward + a.reverse,
                    evidence: vec!["STUN framing in the same UDP flow".into(), "Sustained bidirectional opaque UDP activity; media is not decoded".into(),
                        "Experimental candidate; WhatsApp attribution and participant roles are unverified".into()],
                }).collect();
            }
            tracked.flow
        }).collect();
        flows.sort_by(|a, b| {
            (b.packets_a_to_b + b.packets_b_to_a).cmp(&(a.packets_a_to_b + a.packets_b_to_a))
        });
        flows
    }
}
