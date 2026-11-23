use std::collections::BTreeMap;

use control::{Hook, HookState, KIND_HOOK, Note, Object, State, Table};

use crate::requests::DAY;

pub const REPORT_PERIOD: u64 = 60_000;
pub const REPORT_CHUNK: usize = 64;
const FAILING: u64 = 3 * DAY;
const FRESH: u64 = 3 * REPORT_PERIOD;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamReport {
    pub started: u64,
    pub last_ok: Option<u64>,
    pub failing_since: Option<u64>,
    pub last_status: Option<u16>,
    pub last_at: Option<u64>,
    pub gone: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookReport {
    pub tenant: u32,
    pub generation: u32,
    pub hook: u32,
    pub lost: u64,
    pub stream: Option<StreamReport>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HookStatus {
    pub failing_since: Option<u64>,
    pub last_status: Option<u16>,
    pub lost: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HookStats {
    pub gone: u64,
    pub failing: u64,
    pub write_failed: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Disable {
    pub tenant: u32,
    pub generation: u32,
    pub hook: u32,
    pub active_since: u64,
    pub state: HookState,
}

#[derive(Clone, Copy)]
struct Active {
    tenant: u32,
    generation: u32,
    since: u64,
}

#[derive(Default)]
struct CoreReports {
    complete: Option<u64>,
    pending_at: Option<u64>,
    pending: BTreeMap<u32, HookReport>,
    current: BTreeMap<u32, HookReport>,
}

pub(crate) struct Reports {
    cores: u16,
    active: BTreeMap<u32, Active>,
    by_core: BTreeMap<u16, CoreReports>,
    stats: HookStats,
}

impl Reports {
    pub(crate) fn new(cores: u16) -> Self {
        Self {
            cores,
            active: BTreeMap::new(),
            by_core: BTreeMap::new(),
            stats: HookStats::default(),
        }
    }

    pub(crate) fn change(&mut self, note: &Note, table: &Table, now: u64) {
        match note {
            Note::Snapshot(_) => {
                self.active.clear();
                self.by_core.clear();
            }
            Note::Update(update) => match &update.object {
                Object::Hook(hook)
                    if hook.state == HookState::Active
                        && table.hook(hook.tenant, hook.id).is_none_or(|old| {
                            old.state != HookState::Active
                                || old.generation != hook.generation
                                || old.url != hook.url
                        }) =>
                {
                    self.activate(hook, now);
                }
                _ => {}
            },
            Note::Remove(removal) if removal.kind == KIND_HOOK => self.remove(removal.id),
            Note::Remove(_) => {}
        }
    }

    pub(crate) fn prune(&mut self, table: &Table, now: u64) {
        let stale: Vec<u32> = self
            .active
            .iter()
            .filter(|(id, active)| {
                !table.hook(active.tenant, **id).is_some_and(|hook| {
                    hook.generation == active.generation
                        && table.tenant(active.tenant).is_some_and(|tenant| {
                            tenant.generation == active.generation && tenant.state == State::Active
                        })
                })
            })
            .map(|(&id, _)| id)
            .collect();
        for id in stale {
            self.remove(id);
        }
        for hook in table.every_hook().filter(|hook| {
            table.tenant(hook.tenant).is_some_and(|tenant| {
                tenant.generation == hook.generation && tenant.state == State::Active
            })
        }) {
            self.active.entry(hook.id).or_insert(Active {
                tenant: hook.tenant,
                generation: hook.generation,
                since: now,
            });
        }
    }

    pub(crate) fn activate(&mut self, hook: &Hook, now: u64) {
        self.active.insert(
            hook.id,
            Active {
                tenant: hook.tenant,
                generation: hook.generation,
                since: now,
            },
        );
        for core in self.by_core.values_mut() {
            for reports in [&mut core.current, &mut core.pending] {
                if let Some(report) = reports.get_mut(&hook.id) {
                    report.stream = None;
                }
            }
        }
    }

    pub(crate) fn since(&self, hook: u32) -> Option<u64> {
        self.active.get(&hook).map(|active| active.since)
    }

    fn remove(&mut self, hook: u32) {
        self.active.remove(&hook);
        for core in self.by_core.values_mut() {
            core.current.remove(&hook);
            core.pending.remove(&hook);
        }
    }

    pub(crate) fn status(&self, hook: &Hook) -> HookStatus {
        if !self.active.get(&hook.id).is_some_and(|active| {
            (active.tenant, active.generation) == (hook.tenant, hook.generation)
        }) {
            return HookStatus::default();
        }
        let mut status = HookStatus::default();
        let mut last_at = None;
        for report in self
            .by_core
            .values()
            .filter_map(|core| core.current.get(&hook.id))
            .filter(|report| (report.tenant, report.generation) == (hook.tenant, hook.generation))
        {
            status.lost = status.lost.saturating_add(report.lost);
            let Some(stream) = report.stream else {
                continue;
            };
            status.failing_since = match (status.failing_since, stream.failing_since) {
                (Some(one), Some(two)) => Some(one.min(two)),
                (one, two) => one.or(two),
            };
            if stream.last_status.is_some()
                && stream
                    .last_at
                    .is_some_and(|at| last_at.is_none_or(|last| at >= last))
            {
                last_at = stream.last_at;
                status.last_status = stream.last_status;
            }
        }
        status
    }

    pub(crate) fn ingest(
        &mut self,
        core: u16,
        at: u64,
        reports: Vec<HookReport>,
        last: bool,
        table: &Table,
        now: u64,
    ) -> Vec<Disable> {
        if core >= self.cores {
            return Vec::new();
        }
        let core = self.by_core.entry(core).or_default();
        if core.complete.is_some_and(|complete| at < complete)
            || core.pending_at.is_some_and(|pending| at < pending)
        {
            return Vec::new();
        }
        if core.pending_at != Some(at) {
            core.pending.clear();
            core.pending_at = Some(at);
        }
        for mut report in reports {
            let Some(active) = self.active.get(&report.hook) else {
                continue;
            };
            if (report.tenant, report.generation) != (active.tenant, active.generation) {
                continue;
            }
            if report
                .stream
                .is_some_and(|stream| stream.started < active.since)
            {
                report.stream = None;
            }
            if report.stream.is_none()
                && !table
                    .hook(report.tenant, report.hook)
                    .is_some_and(|hook| hook.state == HookState::Active)
            {
                report.stream = core.current.get(&report.hook).and_then(|old| old.stream);
            }
            core.pending.insert(report.hook, report);
        }
        if !last {
            return Vec::new();
        }
        core.current = std::mem::take(&mut core.pending);
        core.pending_at = None;
        core.complete = Some(at);
        self.decide(table, now)
    }

    fn decide(&self, table: &Table, now: u64) -> Vec<Disable> {
        let fresh = (0..self.cores).all(|core| {
            self.by_core.get(&core).is_some_and(|reports| {
                reports
                    .complete
                    .is_some_and(|at| now.saturating_sub(at) <= FRESH)
            })
        });
        if !fresh {
            return Vec::new();
        }
        let threshold = now.saturating_sub(FAILING);
        let mut out = Vec::new();
        for (&id, active) in &self.active {
            if !table.hook(active.tenant, id).is_some_and(|hook| {
                hook.generation == active.generation && hook.state == HookState::Active
            }) {
                continue;
            }
            let reports: Vec<&HookReport> = self
                .by_core
                .values()
                .filter_map(|core| core.current.get(&id))
                .filter(|report| {
                    (report.tenant, report.generation) == (active.tenant, active.generation)
                })
                .collect();
            let gone = reports
                .iter()
                .any(|report| report.stream.is_some_and(|stream| stream.gone));
            let streams: Vec<StreamReport> =
                reports.iter().filter_map(|report| report.stream).collect();
            let failing = streams
                .iter()
                .all(|stream| stream.last_ok.is_none_or(|ok| ok <= threshold))
                && streams
                    .iter()
                    .filter_map(|stream| stream.failing_since)
                    .min()
                    .is_some_and(|since| since <= threshold);
            let state = if gone {
                Some(HookState::Gone)
            } else if failing {
                Some(HookState::Failing)
            } else {
                None
            };
            if let Some(state) = state {
                out.push(Disable {
                    tenant: active.tenant,
                    generation: active.generation,
                    hook: id,
                    active_since: active.since,
                    state,
                });
            }
        }
        out
    }

    pub(crate) fn current(&self, disable: &Disable) -> bool {
        self.active.get(&disable.hook).is_some_and(|active| {
            active.since == disable.active_since
                && (active.tenant, active.generation) == (disable.tenant, disable.generation)
        })
    }

    pub(crate) fn write_failed(&mut self) {
        self.stats.write_failed = self.stats.write_failed.saturating_add(1);
    }

    pub(crate) fn disabled(&mut self, state: HookState) {
        let count = match state {
            HookState::Gone => &mut self.stats.gone,
            HookState::Failing => &mut self.stats.failing,
            HookState::Active | HookState::Paused => return,
        };
        *count = count.saturating_add(1);
    }

    pub(crate) fn stats(&self) -> HookStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use control::{Snapshot, Tenant};

    fn fixture() -> (Table, Hook) {
        let hook = Hook {
            id: 1,
            tenant: 1,
            generation: 1,
            state: HookState::Active,
            events: 1,
            version: 1,
            previous_until: 0,
            url: "https://hooks.example.org/".into(),
        };
        let tenant = Tenant {
            id: 1,
            generation: 1,
            state: State::Active,
            default_pool: 1,
            pools: vec![1],
            limits: control::Limits::default(),
        };
        let mut table = Table::default();
        table.load(Snapshot {
            version: 1,
            objects: vec![Object::Tenant(tenant), Object::Hook(hook.clone())],
        });
        (table, hook)
    }

    fn report(started: u64, gone: bool, failing_since: Option<u64>) -> HookReport {
        HookReport {
            tenant: 1,
            generation: 1,
            hook: 1,
            lost: 7,
            stream: Some(StreamReport {
                started,
                last_ok: None,
                failing_since,
                last_status: Some(500),
                last_at: Some(started),
                gone,
            }),
        }
    }

    #[test]
    fn a_note_from_an_out_of_range_core_is_ignored() {
        let (table, hook) = fixture();
        let mut reports = Reports::new(2);
        reports.prune(&table, 0);
        let decisions = reports.ingest(2, 1, vec![report(0, true, Some(0))], true, &table, 1);
        assert_eq!(decisions, Vec::new());
        assert_eq!(reports.status(&hook), HookStatus::default());
    }

    #[test]
    fn reports_from_before_reenable_cannot_disable_again() {
        let (table, hook) = fixture();
        let mut reports = Reports::new(2);
        reports.prune(&table, 0);
        reports.ingest(0, 1, vec![report(0, true, Some(0))], true, &table, 1);
        reports.ingest(1, 1, vec![report(0, false, Some(0))], true, &table, 1);
        assert_eq!(reports.status(&hook).lost, 14);
        reports.activate(&hook, 100);
        assert_eq!(reports.status(&hook).lost, 14);
        assert_eq!(reports.status(&hook).last_status, None);
        let now = 3 * DAY + 200;
        assert_eq!(
            reports.ingest(0, now, vec![report(0, true, Some(0))], true, &table, now),
            Vec::new()
        );
        assert_eq!(
            reports.ingest(1, now, vec![report(0, false, Some(0))], true, &table, now),
            Vec::new()
        );
    }

    #[test]
    fn a_hook_failing_on_one_core_with_no_stream_elsewhere_is_disabled() {
        let (table, _) = fixture();
        let mut reports = Reports::new(2);
        reports.prune(&table, 0);
        let now = 3 * DAY + 10;
        let idle = HookReport {
            stream: None,
            ..report(0, false, None)
        };
        reports.ingest(0, now, vec![idle], true, &table, now);
        let decisions = reports.ingest(1, now, vec![report(0, false, Some(5))], true, &table, now);
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].state, HookState::Failing);
    }

    #[test]
    fn a_url_change_starts_fresh() {
        let (table, hook) = fixture();
        let mut reports = Reports::new(1);
        reports.prune(&table, 0);
        reports.ingest(0, 1, vec![report(0, false, Some(0))], true, &table, 1);
        let moved = Hook {
            url: "https://hooks.example.org/new".into(),
            ..hook.clone()
        };
        let note = Note::Update(control::Update {
            version: 2,
            object: Object::Hook(moved),
        });
        reports.change(&note, &table, 50);
        assert_eq!(reports.since(hook.id), Some(50));
        assert_eq!(reports.status(&hook).failing_since, None);
    }

    #[test]
    fn a_disabled_hook_keeps_its_last_stream_status() {
        let (mut table, hook) = fixture();
        let mut reports = Reports::new(1);
        reports.prune(&table, 0);
        reports.ingest(0, 1, vec![report(0, true, Some(0))], true, &table, 1);
        let gone = Hook {
            state: HookState::Gone,
            ..hook.clone()
        };
        table.take(Note::Update(control::Update {
            version: 2,
            object: Object::Hook(gone.clone()),
        }));
        let idle = HookReport {
            stream: None,
            ..report(0, false, None)
        };
        reports.ingest(0, 2, vec![idle], true, &table, 2);
        assert_eq!(reports.status(&gone).last_status, Some(500));
        assert_eq!(reports.status(&gone).failing_since, Some(0));
    }

    #[test]
    fn a_generation_change_prunes_the_old_hook_status() {
        let (mut table, hook) = fixture();
        let mut reports = Reports::new(1);
        reports.prune(&table, 0);
        reports.ingest(0, 1, vec![report(0, false, Some(0))], true, &table, 1);
        assert_eq!(reports.status(&hook).lost, 7);
        let next = Object::Tenant(Tenant {
            generation: 2,
            ..table.tenant(1).expect("tenant").clone()
        });
        let update = control::Update {
            version: 2,
            object: next,
        };
        let note = Note::Update(update);
        reports.change(&note, &table, 2);
        table.take(note);
        reports.prune(&table, 2);
        assert_eq!(reports.status(&hook), HookStatus::default());
    }
}
