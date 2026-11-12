export interface Endpoint { address: string; port: number }
export interface CandidateInterval {
  start_seconds: number; end_seconds: number; duration_seconds: number;
  packets: number; evidence: string[];
}
export interface Flow {
  endpoint_a: Endpoint; endpoint_b: Endpoint;
  first_seen_seconds: number; last_seen_seconds: number;
  packets_a_to_b: number; packets_b_to_a: number;
  frame_bytes: number; stun_packets: number; opaque_packets: number;
  candidate_intervals: CandidateInterval[];
}
export interface CaptureReport {
  total_packets: number; decoded_udp_packets: number; skipped_packets: number;
  truncated_packets: number; duration_seconds: number; flows: Flow[]; warnings: string[];
}
