import { invoke, isTauri } from "@tauri-apps/api/core";
import type { CaptureInterface } from "../types/capture";
import type { CaptureReport } from "../types/analysis";
import type { LiveSnapshot } from "../types/live";
import type { IpInfo } from "../types/enrichment";
export const lookupIp = (address: string) => invoke<IpInfo>("lookup_ip", { address });

export const startCapture = (interfaceName: string) => invoke<void>("start_capture", { interface: interfaceName });
export const stopCapture = () => invoke<void>("stop_capture");
export const resetCapture = () => invoke<void>("reset_capture");
export const getLiveSnapshot = () => invoke<LiveSnapshot>("live_snapshot");

export async function analyzeCapture(path: string): Promise<CaptureReport> {
  if (!isTauri()) throw new Error("Open the desktop app to analyze capture files.");
  return invoke<CaptureReport>("analyze_capture", { path });
}

export async function listInterfaces(): Promise<CaptureInterface[]> {
  if (!isTauri()) throw new Error("Open the desktop app to list capture interfaces.");
  return invoke<CaptureInterface[]>("list_interfaces");
}
