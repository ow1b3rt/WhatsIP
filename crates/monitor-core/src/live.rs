//! One cancellable capture worker with a bounded, latest-value UI snapshot.
use crate::{
    analysis::{Analyzer, Flow},
    packet::decode_ethernet,
};
use serde::Serialize;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Default, Serialize)]
pub struct LiveSnapshot {
    pub started_unix_ms: Option<u64>,
    pub local_addresses: Vec<String>,
    pub call: crate::analysis::lifecycle::CallView,
    pub running: bool,
    pub interface: Option<String>,
    pub elapsed_seconds: f64,
    pub packets: u64,
    pub frame_bytes: u64,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub decoded_udp_packets: u64,
    pub skipped_packets: u64,
    pub truncated_packets: u64,
    pub dropped_packets: Option<u32>,
    pub interface_dropped_packets: Option<u32>,
    pub flows: Vec<Flow>,
    pub error: Option<String>,
}
struct Worker {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}
#[derive(Default)]
pub struct LiveMonitor {
    worker: Mutex<Option<Worker>>,
    snapshot: Arc<Mutex<LiveSnapshot>>,
}
impl LiveMonitor {
    /// Stop the current worker before clearing state so it cannot republish old results.
    pub fn reset(&self) -> Result<(), String> {
        let mut slot = self.worker.lock().map_err(|e| e.to_string())?;
        if let Some(worker) = slot.take() {
            worker.stop.store(true, Ordering::Relaxed);
            worker
                .handle
                .join()
                .map_err(|_| "Capture worker panicked".to_string())?;
        }
        *self.snapshot.lock().map_err(|e| e.to_string())? = LiveSnapshot::default();
        Ok(())
    }

    pub fn snapshot(&self) -> LiveSnapshot {
        self.snapshot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn start(&self, interface: String) -> Result<(), String> {
        let mut slot = self.worker.lock().map_err(|e| e.to_string())?;
        if let Some(worker) = slot.as_ref() {
            if !worker.handle.is_finished() {
                return Err(
                    "Capture is already running. Stop it before changing interfaces.".into(),
                );
            }
        }
        if let Some(worker) = slot.take() {
            let _ = worker.handle.join();
        }
        let device = pcap::Device::list()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|d| d.name == interface)
            .ok_or("The selected interface is no longer available.")?;
        let local_addresses = device
            .addresses
            .iter()
            .map(|a| a.addr.to_string())
            .collect();
        let mut capture = pcap::Capture::from_device(device)
            .map_err(|e| e.to_string())?
            .promisc(false)
            .snaplen(65535)
            .buffer_size(4 * 1024 * 1024)
            .timeout(100)
            .immediate_mode(true)
            .open()
            .map_err(|e| format!("Could not open capture interface: {e}"))?
            .setnonblock()
            .map_err(|e| e.to_string())?;
        if capture.get_datalink() != pcap::Linktype::ETHERNET {
            return Err(
                "Live analysis currently requires an Ethernet/Wi-Fi Ethernet link type.".into(),
            );
        }
        // Capture all frames so IPv6 extension headers/VLAN traffic reach the decoder.
        // No packets are written to disk or sent to the frontend.
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let shared = self.snapshot.clone();
        *shared.lock().map_err(|e| e.to_string())? = LiveSnapshot {
            started_unix_ms: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_millis() as u64,
            ),
            local_addresses,
            running: true,
            interface: Some(interface),
            ..Default::default()
        };
        let handle = thread::Builder::new().name("whatsip-capture".into()).spawn(move || {
            let mut current = shared.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let mut analyzer = Analyzer::default();
            let mut tracker = crate::analysis::lifecycle::CallTracker::default();
            let started = Instant::now();
            let mut published = Instant::now();
            let mut origin = None;
            let mut previous = 0.0f64;
            while !signal.load(Ordering::Relaxed) {
                let mut idle = false;
                match capture.next_packet() {
                    Ok(packet) => {
                        current.packets += 1;
                        current.frame_bytes += packet.data.len() as u64;
                        if packet.header.caplen < packet.header.len { current.truncated_packets += 1; }
                        let stamp = packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;
                        let (first_stamp, first_elapsed) = *origin.get_or_insert((stamp, started.elapsed().as_secs_f64()));
                        // Anchor packet timestamps to monitor start and tolerate wall-clock rollback.
                        let time = (first_elapsed + stamp - first_stamp).max(previous);
                        previous = time;
                        let frame_size = packet.data.len();
                        if let Some(packet) = decode_ethernet(packet.data) {
                            current.decoded_udp_packets += 1;
                            analyzer.observe(time, frame_size, packet);
                        } else { current.skipped_packets += 1; }
                        if analyzer.flow_count() > 4096 {
                            current.error = Some("Capture stopped at the 4096-flow safety limit. Restart to reset.".into());
                            break;
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => idle = true,
                    Err(error) => { current.error = Some(format!("Capture failed: {error}")); break; }
                }
                if published.elapsed() >= Duration::from_millis(500) {
                    publish(&mut capture, &mut analyzer, &mut tracker, &mut current, &shared, started.elapsed().as_secs_f64());
                    published = Instant::now();
                }
                if idle { thread::sleep(Duration::from_millis(10)); }
            }
            current.running = false;
            publish(&mut capture, &mut analyzer, &mut tracker, &mut current, &shared, started.elapsed().as_secs_f64());
        }).map_err(|e| {
            let mut snapshot = self.snapshot.lock().unwrap_or_else(|p| p.into_inner());
            snapshot.running = false; snapshot.error = Some(e.to_string()); e.to_string()
        })?;
        *slot = Some(Worker { stop, handle });
        Ok(())
    }
    pub fn stop(&self) -> Result<(), String> {
        let mut slot = self.worker.lock().map_err(|e| e.to_string())?;
        if let Some(worker) = slot.take() {
            worker.stop.store(true, Ordering::Relaxed);
            worker
                .handle
                .join()
                .map_err(|_| "Capture worker panicked".to_string())?;
        }
        Ok(())
    }
}
impl Drop for LiveMonitor {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn publish(
    capture: &mut pcap::Capture<pcap::Active>,
    analyzer: &mut Analyzer,
    tracker: &mut crate::analysis::lifecycle::CallTracker,
    current: &mut LiveSnapshot,
    shared: &Mutex<LiveSnapshot>,
    elapsed: f64,
) {
    let prior = shared.lock().unwrap_or_else(|e| e.into_inner());
    let delta = elapsed - prior.elapsed_seconds;
    if delta > 0.0 {
        current.packets_per_second = (current.packets - prior.packets) as f64 / delta;
        current.bytes_per_second = (current.frame_bytes - prior.frame_bytes) as f64 / delta;
    }
    drop(prior);
    current.elapsed_seconds = elapsed;
    analyzer.prune_live(elapsed);
    current.flows = analyzer.snapshot();
    current.call = tracker.update(&current.flows, elapsed, current.running);
    if let Ok(stats) = capture.stats() {
        current.dropped_packets = Some(stats.dropped);
        current.interface_dropped_packets = Some(stats.if_dropped);
    }
    *shared.lock().unwrap_or_else(|e| e.into_inner()) = current.clone();
}
