#[tauri::command]
pub async fn list_interfaces() -> Result<Vec<monitor_core::capture::CaptureInterface>, String> {
    tauri::async_runtime::spawn_blocking(monitor_core::capture::list_interfaces)
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn lookup_ip(
    address: String,
    lookup: tauri::State<'_, crate::enrichment::IpLookup>,
) -> Result<crate::enrichment::IpInfo, String> {
    lookup.lookup(address).await
}

#[tauri::command]
pub async fn start_capture(
    interface: String,
    monitor: tauri::State<'_, std::sync::Arc<monitor_core::live::LiveMonitor>>,
) -> Result<(), String> {
    let monitor = monitor.inner().clone();
    tauri::async_runtime::spawn_blocking(move || monitor.start(interface))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn stop_capture(
    monitor: tauri::State<'_, std::sync::Arc<monitor_core::live::LiveMonitor>>,
) -> Result<(), String> {
    let monitor = monitor.inner().clone();
    tauri::async_runtime::spawn_blocking(move || monitor.stop())
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn live_snapshot(
    monitor: tauri::State<'_, std::sync::Arc<monitor_core::live::LiveMonitor>>,
) -> monitor_core::live::LiveSnapshot {
    monitor.snapshot()
}

#[tauri::command]
pub async fn reset_capture(
    monitor: tauri::State<'_, std::sync::Arc<monitor_core::live::LiveMonitor>>,
) -> Result<(), String> {
    let monitor = monitor.inner().clone();
    tauri::async_runtime::spawn_blocking(move || monitor.reset())
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn analyze_capture(path: String) -> Result<monitor_core::capture::CaptureReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        monitor_core::capture::analyze_file(std::path::Path::new(&path))
    })
    .await
    .map_err(|error| error.to_string())?
}
