//! Traffic-based estimates, not decoded application call events.
#[cfg(test)]
mod tests;
use super::{CandidateInterval, Flow};
use crate::models::Endpoint;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallStatus {
    #[default]
    Idle,
    Ringing,
    Connected,
    Ended,
    Unanswered,
    Interrupted,
}
#[derive(Clone, Debug, Serialize)]
pub struct CompletedCandidate {
    pub endpoint_a: Endpoint,
    pub endpoint_b: Endpoint,
    pub activity: CandidateInterval,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct CallView {
    pub status: CallStatus,
    pub duration_seconds: f64,
    pub top_candidate: Option<CompletedCandidate>,
}
pub struct CallTracker {
    view: CallView,
    start: f64,
    cutoff: f64,
    latest_setup: f64,
    last_activity: f64,
    best: Option<CompletedCandidate>,
}
impl Default for CallTracker {
    fn default() -> Self {
        Self {
            view: CallView::default(),
            start: 0.0,
            cutoff: -1.0,
            latest_setup: -1.0,
            last_activity: 0.0,
            best: None,
        }
    }
}
impl CallTracker {
    pub fn update(&mut self, flows: &[Flow], now: f64, running: bool) -> CallView {
        if !running {
            if matches!(
                self.view.status,
                CallStatus::Connected | CallStatus::Ringing
            ) {
                self.view.status = CallStatus::Interrupted;
                self.view.top_candidate = None;
            }
            return self.view.clone();
        }
        let setup = flows
            .iter()
            .filter(|f| f.endpoint_a.port == 3478 || f.endpoint_b.port == 3478)
            .filter_map(|f| f.last_setup_seconds)
            .max_by(f64::total_cmp)
            .unwrap_or(-1.0);
        let new_setup = setup > self.latest_setup && setup > self.cutoff && now - setup <= 3.0;
        self.latest_setup = self.latest_setup.max(setup);
        let active: Vec<_> = flows
            .iter()
            .flat_map(|flow| {
                flow.candidate_intervals
                    .iter()
                    .map(move |activity| (flow, activity))
            })
            .filter(|(_, a)| a.start_seconds > self.cutoff && now - a.end_seconds <= 3.0)
            .collect();
        if !matches!(
            self.view.status,
            CallStatus::Ringing | CallStatus::Connected
        ) && (new_setup || !active.is_empty())
        {
            self.start = if new_setup {
                setup
            } else {
                active
                    .iter()
                    .map(|(_, a)| a.start_seconds)
                    .min_by(f64::total_cmp)
                    .unwrap()
            };
            self.best = None;
            self.last_activity = self.start;
            self.view = CallView {
                status: CallStatus::Ringing,
                ..Default::default()
            };
        }
        if matches!(
            self.view.status,
            CallStatus::Ringing | CallStatus::Connected
        ) {
            for (flow, activity) in active {
                if activity.end_seconds < self.start {
                    continue;
                }
                self.last_activity = self.last_activity.max(activity.end_seconds);
                let better = self.best.as_ref().is_none_or(|b| {
                    activity.packets > b.activity.packets
                        || (activity.packets == b.activity.packets
                            && activity.duration_seconds > b.activity.duration_seconds)
                });
                if better {
                    self.best = Some(CompletedCandidate {
                        endpoint_a: flow.endpoint_a.clone(),
                        endpoint_b: flow.endpoint_b.clone(),
                        activity: activity.clone(),
                    });
                }
                self.view.status = CallStatus::Connected;
            }
            if self.view.status == CallStatus::Connected {
                self.view.duration_seconds = self
                    .best
                    .as_ref()
                    .map_or(0.0, |b| b.activity.duration_seconds);
                if now - self.last_activity > 3.0 {
                    self.view.status = CallStatus::Ended;
                    self.view.top_candidate = self.best.clone();
                    self.cutoff = now;
                }
            } else if now - self.latest_setup.max(self.start) > 15.0 || now - self.start > 90.0 {
                self.view.status = CallStatus::Unanswered;
                self.view.top_candidate = None;
                self.cutoff = now;
            }
        }
        self.view.clone()
    }
}
