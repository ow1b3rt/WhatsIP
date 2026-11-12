//! Replay a capture with virtual 500ms ticks to inspect live status transitions.
use monitor_core::{
    analysis::{
        lifecycle::{CallStatus, CallTracker},
        Analyzer,
    },
    packet::decode_ethernet,
};
fn main() -> Result<(), String> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("Provide a capture file path")?;
    let mut capture =
        pcap::Capture::from_file(std::path::Path::new(&path)).map_err(|e| e.to_string())?;
    if capture.get_datalink() != pcap::Linktype::ETHERNET {
        return Err("Ethernet required".into());
    }
    let mut analyzer = Analyzer::default();
    let mut tracker = CallTracker::default();
    let mut tick = 0.0;
    let mut origin = None;
    let mut last = CallStatus::Idle;
    let mut update = |analyzer: &Analyzer, time: f64| {
        let call = tracker.update(&analyzer.snapshot(), time, true);
        if call.status != last {
            println!("{time:.1}s: {:?}", call.status);
            if let Some(top) = call.top_candidate {
                println!(
                    "Top candidate: {:.6}s, {} activity packets",
                    top.activity.duration_seconds, top.activity.packets
                );
            }
            last = call.status;
        }
    };
    loop {
        let packet = match capture.next_packet() {
            Ok(p) => p,
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(e.to_string()),
        };
        let stamp = packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;
        let time = stamp - *origin.get_or_insert(stamp);
        while tick < time {
            update(&analyzer, tick);
            tick += 0.5;
        }
        if let Some(datagram) = decode_ethernet(packet.data) {
            analyzer.observe(time, packet.data.len(), datagram);
        }
    }
    let finish = tick + 4.0;
    while tick <= finish {
        update(&analyzer, tick);
        tick += 0.5;
    }
    Ok(())
}
