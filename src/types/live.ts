import type { Flow, CandidateInterval, Endpoint } from "./analysis";
export interface LiveSnapshot {
  started_unix_ms: number | null;
  local_addresses: string[];
  call: {
    status: "idle" | "ringing" | "connected" | "ended" | "unanswered" | "interrupted";
    duration_seconds: number;
    top_candidate: { endpoint_a: Endpoint; endpoint_b: Endpoint; activity: CandidateInterval } | null;
  };
  running: boolean; interface: string | null; elapsed_seconds: number;
  packets: number; frame_bytes: number; decoded_udp_packets: number;
  packets_per_second: number; bytes_per_second: number;
  skipped_packets: number; truncated_packets: number;
  dropped_packets: number | null; interface_dropped_packets: number | null;
  flows: Flow[]; error: string | null;
}
