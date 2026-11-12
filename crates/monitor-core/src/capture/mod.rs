use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct CaptureReport {
    pub total_packets: u64,
    pub decoded_udp_packets: u64,
    pub skipped_packets: u64,
    pub truncated_packets: u64,
    pub duration_seconds: f64,
    pub flows: Vec<crate::analysis::Flow>,
    pub warnings: Vec<String>,
}

#[cfg(feature = "live-capture")]
pub fn analyze_file(path: &std::path::Path) -> Result<CaptureReport, String> {
    use crate::{analysis::Analyzer, packet::decode_ethernet};
    let mut capture = pcap::Capture::from_file(path).map_err(|e| e.to_string())?;
    if capture.get_datalink() != pcap::Linktype::ETHERNET {
        return Err(
            "Only Ethernet captures (including VLAN) are supported in this version.".into(),
        );
    }
    let mut analyzer = Analyzer::default();
    let mut report = CaptureReport { total_packets: 0, decoded_udp_packets: 0, skipped_packets: 0,
        truncated_packets: 0, duration_seconds: 0.0, flows: vec![],
        warnings: vec!["Experimental generic UDP/STUN candidates, not confirmed WhatsApp calls. Participant roles are unknown; endpoints may be relays.".into(),
        "Only complete Ethernet IPv4/IPv6 UDP packets are analyzed. TCP, fragments, and unsupported packets are skipped; checksums are not verified.".into()] };
    let mut origin = None;
    let mut previous = 0.0;
    loop {
        let packet = match capture.next_packet() {
            Ok(packet) => packet,
            Err(pcap::Error::NoMorePackets) => break,
            Err(error) => return Err(format!("Capture read failed: {error}")),
        };
        report.total_packets += 1;
        // libpcap's default offline precision is microseconds, even for pcapng.
        let timestamp =
            packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;
        let start = *origin.get_or_insert(timestamp);
        let time = timestamp - start;
        if time < previous {
            return Err(
                "Out-of-order timestamps are not supported; sort the capture first.".into(),
            );
        }
        previous = time;
        report.duration_seconds = time;
        if packet.header.caplen < packet.header.len {
            report.truncated_packets += 1;
        }
        if let Some(datagram) = decode_ethernet(packet.data) {
            report.decoded_udp_packets += 1;
            analyzer.observe(time, packet.data.len(), datagram);
        } else {
            report.skipped_packets += 1;
        }
        // Bound work and memory for the initial synchronous file import.
        if report.total_packets > 1_000_000 {
            return Err("Capture exceeds the initial one-million-packet analysis limit.".into());
        }
    }
    report.flows = analyzer.finish();
    Ok(report)
}

#[derive(Debug, Serialize)]
pub struct CaptureInterface {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
}

#[cfg(feature = "live-capture")]
pub fn list_interfaces() -> Result<Vec<CaptureInterface>, pcap::Error> {
    pcap::Device::list().map(|devices| {
        devices
            .into_iter()
            .map(|device| CaptureInterface {
                name: device.name,
                description: device.desc,
                addresses: device
                    .addresses
                    .into_iter()
                    .map(|a| a.addr.to_string())
                    .collect(),
            })
            .collect()
    })
}
