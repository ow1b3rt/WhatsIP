mod commands;
mod enrichment;
use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        .manage(enrichment::IpLookup::default())
        .manage(std::sync::Arc::new(
            monitor_core::live::LiveMonitor::default(),
        ))
        .invoke_handler(tauri::generate_handler![
            commands::list_interfaces,
            commands::analyze_capture,
            commands::start_capture,
            commands::stop_capture,
            commands::reset_capture,
            commands::lookup_ip,
            commands::live_snapshot
        ])
        .build(tauri::generate_context!())
        .expect("failed to build WhatsIP desktop application")
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                let _ = app
                    .state::<std::sync::Arc<monitor_core::live::LiveMonitor>>()
                    .stop();
            }
        });
}
