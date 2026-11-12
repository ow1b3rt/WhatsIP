fn main() {
    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("Usage: cargo run -p monitor-core --features live-capture --example analyze -- <capture>");
        std::process::exit(2);
    };
    match monitor_core::capture::analyze_file(std::path::Path::new(&path)) {
        Ok(report) => {
            println!(
                "{} packets, {} UDP, {:.3}s capture",
                report.total_packets, report.decoded_udp_packets, report.duration_seconds
            );
            for flow in report.flows {
                for interval in flow.candidate_intervals {
                    println!("{:?} <-> {:?}: {:.6}s to {:.6}s = {:.6}s ({} opaque packets, {} STUN packets in flow)",
                        flow.endpoint_a, flow.endpoint_b, interval.start_seconds, interval.end_seconds, interval.duration_seconds, interval.packets, flow.stun_packets);
                }
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
