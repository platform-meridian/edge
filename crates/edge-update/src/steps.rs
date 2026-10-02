//! The update as a person follows it: a few steps, each phase belonging to
//! one, each recorded as it is taken. A release needs only some of them.

use serde::{Deserialize, Serialize};

use crate::engine::Phase;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Upload,
    Verify,
    Stage,
    Install,
    Reboot,
    OsTrial,
    Stack,
    Trial,
    Commit,
}

const ALL: [Step; 9] = [
    Step::Upload,
    Step::Verify,
    Step::Stage,
    Step::Install,
    Step::Reboot,
    Step::OsTrial,
    Step::Stack,
    Step::Trial,
    Step::Commit,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Pending,
    Running,
    Done,
    Failed,
    Skipped,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Taken {
    pub step: Step,
    pub state: State,
    pub started: i64,
    #[serde(default)]
    pub finished: i64,
}

pub fn of(phase: &Phase) -> Option<Step> {
    Some(match phase {
        Phase::Idle => return None,
        Phase::Verifying { .. } => Step::Verify,
        Phase::Starting | Phase::Importing | Phase::Snapshotting | Phase::Staging => Step::Stage,
        Phase::Installing => Step::Install,
        Phase::Rebooting { .. } => Step::Reboot,
        Phase::Trial | Phase::Settling => Step::OsTrial,
        Phase::Seeding | Phase::AwaitingGood | Phase::Repointing { .. } => Step::Stack,
        Phase::Judging { .. } => Step::Trial,
        Phase::Collecting => Step::Commit,
    })
}

/// The steps a release needs: none of the OS's when the unit runs it already.
pub fn plan(os_changes: bool) -> Vec<Step> {
    ALL.into_iter()
        .filter(|s| os_changes || !matches!(s, Step::Install | Step::Reboot | Step::OsTrial))
        .collect()
}

/// Starts `step`, ending the one running; nothing if it runs already.
pub fn enter(taken: &mut Vec<Taken>, step: Step, now: i64) {
    if taken
        .last()
        .is_some_and(|t| t.step == step && t.state == State::Running)
    {
        return;
    }
    close(taken, State::Done, now);
    taken.push(Taken {
        step,
        state: State::Running,
        started: now,
        finished: 0,
    });
}

/// Ends the step running, as `state`.
pub fn close(taken: &mut [Taken], state: State, now: i64) {
    if let Some(t) = taken.last_mut().filter(|t| t.state == State::Running) {
        t.state = state;
        t.finished = now;
    }
}

/// The steps taken, then the rest of `plan` still to come, in order. A step
/// taken stays though the plan lacks it, and a step skipped is left out.
pub fn merged(taken: &[Taken], plan: &[Step]) -> Vec<Taken> {
    ALL.into_iter()
        .filter_map(|s| match taken.iter().rev().find(|t| t.step == s) {
            Some(t) if t.state == State::Skipped && !plan.contains(&s) => None,
            Some(t) => Some(t.clone()),
            None => plan.contains(&s).then_some(Taken {
                step: s,
                state: State::Pending,
                started: 0,
                finished: 0,
            }),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(t: &[Taken]) -> Vec<(Step, State)> {
        t.iter().map(|t| (t.step, t.state)).collect()
    }

    #[test]
    fn a_release_without_a_new_os_needs_no_os_steps() {
        assert_eq!(
            plan(false),
            [
                Step::Upload,
                Step::Verify,
                Step::Stage,
                Step::Stack,
                Step::Trial,
                Step::Commit
            ]
        );
        assert_eq!(plan(true).len(), 9);
    }

    #[test]
    fn entering_a_step_ends_the_last_once() {
        let mut t = Vec::new();
        enter(&mut t, Step::Stage, 10);
        enter(&mut t, Step::Stage, 20);
        enter(&mut t, Step::Install, 30);
        assert_eq!(
            t,
            [
                Taken {
                    step: Step::Stage,
                    state: State::Done,
                    started: 10,
                    finished: 30
                },
                Taken {
                    step: Step::Install,
                    state: State::Running,
                    started: 30,
                    finished: 0
                },
            ]
        );
        close(&mut t, State::Failed, 40);
        close(&mut t, State::Done, 50);
        assert_eq!((t[1].state, t[1].finished), (State::Failed, 40));
    }

    #[test]
    fn the_plan_fills_in_what_is_still_to_come() {
        let mut t = Vec::new();
        enter(&mut t, Step::Verify, 1);
        enter(&mut t, Step::Stage, 2);
        assert_eq!(
            kinds(&merged(&t, &plan(false))),
            [
                (Step::Upload, State::Pending),
                (Step::Verify, State::Done),
                (Step::Stage, State::Running),
                (Step::Stack, State::Pending),
                (Step::Trial, State::Pending),
                (Step::Commit, State::Pending),
            ]
        );
        // The config would not apply without a reboot: the OS came after all.
        enter(&mut t, Step::Install, 3);
        assert!(
            merged(&t, &plan(false))
                .iter()
                .any(|t| t.step == Step::Install)
        );
        // Skipped, as planned: not shown.
        t.last_mut().unwrap().state = State::Skipped;
        assert!(
            !merged(&t, &plan(false))
                .iter()
                .any(|t| t.step == Step::Install)
        );
        assert!(
            merged(&t, &plan(true))
                .iter()
                .any(|t| t.state == State::Skipped)
        );
    }

    #[test]
    fn every_phase_but_idle_belongs_to_a_step() {
        assert_eq!(of(&Phase::Idle), None);
        assert_eq!(of(&Phase::Snapshotting), Some(Step::Stage));
        assert_eq!(of(&Phase::Settling), Some(Step::OsTrial));
        assert_eq!(
            of(&Phase::Judging {
                rolled_back: String::new()
            }),
            Some(Step::Trial)
        );
        assert_eq!(of(&Phase::Collecting), Some(Step::Commit));
    }
}
