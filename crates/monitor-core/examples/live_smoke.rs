//! Short real-interface lifecycle check. Never saves packets.
use monitor_core::live::LiveMonitor;
fn main() -> Result<(), String> {
    let devices = pcap::Device::list().map_err(|e| e.to_string())?;
    let Some(name) = std::env::args().nth(1) else {
        for device in devices {
            println!("{} {:?}", device.name, device.desc);
        }
        return Ok(());
    };
    let monitor = LiveMonitor::default();
    monitor.start(name.clone())?;
    assert!(
        monitor.start(name.clone()).is_err(),
        "must reject duplicate start"
    );
    std::thread::sleep(std::time::Duration::from_secs(2));
    let live = monitor.snapshot();
    assert!(live.running, "capture failed: {:?}", live.error);
    let stopped = std::time::Instant::now();
    monitor.stop()?;
    assert!(!monitor.snapshot().running);
    assert!(stopped.elapsed().as_secs_f64() < 2.0);
    println!(
        "Live snapshot: {} packets, {} UDP, {} flows; stopped in {:?}",
        live.packets,
        live.decoded_udp_packets,
        live.flows.len(),
        stopped.elapsed()
    );
    monitor.start(name)?;
    monitor.stop()?;
    println!("Restart and immediate stop succeeded");
    Ok(())
}
