use super::*;
fn feed(analyzer: &mut Analyzer, time: f64, reverse: bool, stun: bool) {
    let a = Endpoint {
        address: "192.168.1.1".parse().unwrap(),
        port: 9000,
    };
    let b = Endpoint {
        address: "192.168.1.2".parse().unwrap(),
        port: 9001,
    };
    let mut control = [0; 20];
    control[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
    analyzer.observe(
        time,
        100,
        Datagram {
            source: if reverse { b.clone() } else { a.clone() },
            destination: if reverse { a } else { b },
            payload: if stun { &control } else { &[0xff; 24] },
        },
    );
}
#[test]
fn opaque_udp_without_control_or_without_reverse_is_not_a_candidate() {
    for control in [false, true] {
        let mut a = Analyzer::default();
        if control {
            feed(&mut a, 0.0, false, true);
            feed(&mut a, 0.1, true, true);
        }
        for i in 0..30 {
            feed(&mut a, 1.0 + i as f64 / 10.0, !control && i % 2 == 0, false);
        }
        assert!(a.finish()[0].candidate_intervals.is_empty());
    }
}
#[test]
fn setup_is_excluded_and_idle_gap_splits_activity() {
    let mut a = Analyzer::default();
    feed(&mut a, 0.0, false, true);
    feed(&mut a, 0.1, true, true);
    for start in [10.0, 30.0] {
        for i in 0..30 {
            feed(&mut a, start + i as f64 / 10.0, i % 2 == 0, false);
        }
    }
    let flows = a.finish();
    let flow = &flows[0];
    assert_eq!(flows.len(), 1);
    assert_eq!(flow.packets_a_to_b, 31);
    assert_eq!(flow.packets_b_to_a, 31);
    assert_eq!(flow.candidate_intervals.len(), 2);
    assert_eq!(flow.candidate_intervals[0].start_seconds, 10.0);
    assert!((flow.candidate_intervals[0].duration_seconds - 2.9).abs() < 1e-9);
}

#[test]
fn live_snapshots_keep_tracking_and_expire_idle_flows() {
    let mut a = Analyzer::default();
    feed(&mut a, 0.0, false, true);
    feed(&mut a, 0.1, true, true);
    for i in 0..30 {
        feed(&mut a, 1.0 + i as f64 / 10.0, i % 2 == 0, false);
    }
    let first = a.snapshot()[0].candidate_intervals[0].duration_seconds;
    feed(&mut a, 4.5, false, false);
    let second = a.snapshot();
    assert!(second[0].candidate_intervals[0].duration_seconds > first);
    a.prune_live(124.0);
    assert_eq!(a.flow_count(), 1);
    a.prune_live(125.0);
    assert_eq!(a.flow_count(), 0);
}
