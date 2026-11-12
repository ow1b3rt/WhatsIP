use super::*;
fn flow(packets: u64, end: f64) -> Flow {
    Flow {
        endpoint_a: Endpoint {
            address: "192.168.1.67".parse().unwrap(),
            port: 60000,
        },
        endpoint_b: Endpoint {
            address: "203.0.113.1".parse().unwrap(),
            port: 3478,
        },
        first_seen_seconds: 1.0,
        last_seen_seconds: end,
        last_setup_seconds: Some(1.0),
        packets_a_to_b: packets / 2,
        packets_b_to_a: packets / 2,
        frame_bytes: 10000,
        stun_packets: 2,
        opaque_packets: packets,
        candidate_intervals: if packets == 0 {
            vec![]
        } else {
            vec![CandidateInterval {
                start_seconds: 3.0,
                end_seconds: end,
                duration_seconds: end - 3.0,
                packets,
                evidence: vec![],
            }]
        },
    }
}
#[test]
fn result_is_hidden_until_connected_activity_ends_and_remains_stable() {
    let mut tracker = CallTracker::default();
    let setup = flow(0, 1.0);
    assert_eq!(tracker.update(&[], 0.0, true).status, CallStatus::Idle);
    let ringing = tracker.update(&[setup], 1.0, true);
    assert_eq!(ringing.status, CallStatus::Ringing);
    assert!(ringing.top_candidate.is_none());
    let candidate = flow(50, 8.0);
    let connected = tracker.update(&[candidate.clone()], 8.0, true);
    assert_eq!(connected.status, CallStatus::Connected);
    assert!(connected.top_candidate.is_none());
    assert_eq!(
        tracker.update(&[candidate.clone()], 10.9, true).status,
        CallStatus::Connected
    );
    let ended = tracker.update(&[candidate.clone()], 11.1, true);
    assert_eq!(ended.status, CallStatus::Ended);
    assert_eq!(ended.top_candidate.unwrap().activity.packets, 50);
    assert_eq!(
        tracker.update(&[candidate], 20.0, true).status,
        CallStatus::Ended
    );
    assert_eq!(tracker.update(&[], 200.0, true).status, CallStatus::Ended);
}
#[test]
fn picks_one_strongest_candidate() {
    let mut tracker = CallTracker::default();
    let mut stronger = flow(100, 9.0);
    stronger.endpoint_b.port = 3478;
    let weaker = flow(50, 8.0);
    tracker.update(&[weaker.clone(), stronger.clone()], 9.0, true);
    let ended = tracker.update(&[weaker, stronger], 12.1, true);
    assert_eq!(ended.top_candidate.unwrap().activity.packets, 100);
}
#[test]
fn unanswered_and_manual_stop_do_not_produce_results() {
    let mut tracker = CallTracker::default();
    tracker.update(&[flow(0, 1.0)], 1.0, true);
    let unanswered = tracker.update(&[flow(0, 1.0)], 17.0, true);
    assert_eq!(unanswered.status, CallStatus::Unanswered);
    assert!(unanswered.top_candidate.is_none());
    let mut tracker = CallTracker::default();
    tracker.update(&[flow(50, 8.0)], 8.0, true);
    let stopped = tracker.update(&[flow(50, 8.0)], 8.5, false);
    assert_eq!(stopped.status, CallStatus::Interrupted);
    assert!(stopped.top_candidate.is_none());
}
#[test]
fn new_setup_clears_previous_completed_result() {
    let mut tracker = CallTracker::default();
    tracker.update(&[flow(50, 8.0)], 8.0, true);
    tracker.update(&[flow(50, 8.0)], 12.0, true);
    let mut next = flow(0, 15.0);
    next.last_setup_seconds = Some(15.0);
    let ringing = tracker.update(&[next], 15.0, true);
    assert_eq!(ringing.status, CallStatus::Ringing);
    assert!(ringing.top_candidate.is_none());
}

#[test]
fn direct_high_port_ipv6_activity_connects_without_claiming_ringing() {
    let mut tracker = CallTracker::default();
    let mut direct = flow(100, 8.0);
    direct.endpoint_a.address = "2400:1a00:4ba7:3302:7df4:6180:9c56:8ab0".parse().unwrap();
    direct.endpoint_a.port = 64843;
    direct.endpoint_b.address = "2400:1a00:3b85:825e:1560:57fb:ee7d:ab43".parse().unwrap();
    direct.endpoint_b.port = 50668;
    direct.last_setup_seconds = None;
    let connected = tracker.update(&[direct.clone()], 8.0, true);
    assert_eq!(connected.status, CallStatus::Connected);
    assert!(connected.top_candidate.is_none());
    let ended = tracker.update(&[direct], 11.5, true);
    assert_eq!(ended.status, CallStatus::Ended);
    assert_eq!(ended.top_candidate.unwrap().endpoint_b.port, 50668);
}
