use std::collections::BTreeMap;
use std::time::Duration;

use crate::control::{RuntimeControlOptions, RuntimeLoopSignal, RuntimeTickOptions};
use crate::panel::types::UserInfo;

#[derive(Clone, Debug, PartialEq)]
pub struct RuntimeLoopOptions {
    pub control: RuntimeControlOptions,
    pub max_ticks: Option<usize>,
    pub tick_interval: Duration,
    pub user_refresh_interval: usize,
    pub panel_report_interval: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeLoopExit {
    pub ticks: usize,
    pub reason: RuntimeLoopExitReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeLoopExitReason {
    MaxTicks,
    Signal(RuntimeLoopSignal),
}

pub trait RuntimeLoopCallbacks {
    fn refresh_users(&mut self) -> Result<BTreeMap<String, Vec<UserInfo>>, String>;
    fn run_tick(&mut self, options: RuntimeTickOptions) -> Result<RuntimeLoopSignal, String>;

    fn sleep(&mut self, duration: Duration) -> Result<(), String> {
        std::thread::sleep(duration);
        Ok(())
    }
}

impl Default for RuntimeLoopOptions {
    fn default() -> Self {
        Self {
            control: RuntimeControlOptions::default(),
            max_ticks: None,
            tick_interval: Duration::from_secs(60),
            user_refresh_interval: 1,
            panel_report_interval: 1,
        }
    }
}

pub fn run_runtime_loop<C>(
    callbacks: &mut C,
    options: RuntimeLoopOptions,
) -> Result<RuntimeLoopExit, String>
where
    C: RuntimeLoopCallbacks,
{
    let mut ticks = 0usize;
    loop {
        if let Some(max_ticks) = options.max_ticks {
            if ticks >= max_ticks {
                return Ok(RuntimeLoopExit {
                    ticks,
                    reason: RuntimeLoopExitReason::MaxTicks,
                });
            }
        }

        ticks += 1;
        let users_by_node_tag = if should_run(ticks, options.user_refresh_interval) {
            callbacks.refresh_users()?
        } else {
            BTreeMap::new()
        };
        let signal = callbacks.run_tick(RuntimeTickOptions {
            control: options.control.clone(),
            report_to_panel: should_run(ticks, options.panel_report_interval),
            users_by_node_tag,
        })?;
        if signal != RuntimeLoopSignal::Continue {
            return Ok(RuntimeLoopExit {
                ticks,
                reason: RuntimeLoopExitReason::Signal(signal),
            });
        }
        if let Some(max_ticks) = options.max_ticks {
            if ticks >= max_ticks {
                return Ok(RuntimeLoopExit {
                    ticks,
                    reason: RuntimeLoopExitReason::MaxTicks,
                });
            }
        }

        if options.tick_interval > Duration::from_secs(0) {
            callbacks.sleep(options.tick_interval)?;
        }
    }
}

pub fn should_run(tick: usize, interval: usize) -> bool {
    interval > 0 && tick % interval == 0
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::{
        run_runtime_loop, should_run, RuntimeLoopCallbacks, RuntimeLoopExit,
        RuntimeLoopExitReason, RuntimeLoopOptions,
    };
    use crate::control::{RuntimeLoopSignal, RuntimeTickOptions};
    use crate::machine::MachineUpgradeCommand;
    use crate::panel::types::UserInfo;

    #[test]
    fn should_run_matches_tick_interval() {
        assert!(should_run(1, 1));
        assert!(!should_run(1, 2));
        assert!(should_run(2, 2));
        assert!(!should_run(2, 0));
    }

    #[test]
    fn loop_stops_after_max_ticks() {
        let mut callbacks = FakeCallbacks::default();

        let exit = run_runtime_loop(
            &mut callbacks,
            RuntimeLoopOptions {
                max_ticks: Some(3),
                tick_interval: Duration::from_secs(0),
                ..RuntimeLoopOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            exit,
            RuntimeLoopExit {
                ticks: 3,
                reason: RuntimeLoopExitReason::MaxTicks,
            }
        );
        assert_eq!(callbacks.ticks.len(), 3);
        assert_eq!(callbacks.refreshes, 3);
    }

    #[test]
    fn loop_passes_periodic_user_refresh_and_report_flags() {
        let mut callbacks = FakeCallbacks::default();

        let exit = run_runtime_loop(
            &mut callbacks,
            RuntimeLoopOptions {
                max_ticks: Some(4),
                tick_interval: Duration::from_secs(0),
                user_refresh_interval: 2,
                panel_report_interval: 3,
                ..RuntimeLoopOptions::default()
            },
        )
        .unwrap();

        assert_eq!(exit.reason, RuntimeLoopExitReason::MaxTicks);
        assert_eq!(callbacks.refreshes, 2);
        assert!(callbacks.ticks[0].users_by_node_tag.is_empty());
        assert!(!callbacks.ticks[1].users_by_node_tag.is_empty());
        assert!(!callbacks.ticks[0].report_to_panel);
        assert!(callbacks.ticks[2].report_to_panel);
    }

    #[test]
    fn loop_exits_on_reload_or_upgrade_signal() {
        let mut callbacks = FakeCallbacks {
            signal_at: Some(2),
            signal: RuntimeLoopSignal::Reload,
            ..FakeCallbacks::default()
        };

        let exit = run_runtime_loop(
            &mut callbacks,
            RuntimeLoopOptions {
                max_ticks: Some(5),
                tick_interval: Duration::from_secs(0),
                ..RuntimeLoopOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            exit.reason,
            RuntimeLoopExitReason::Signal(RuntimeLoopSignal::Reload)
        );
        assert_eq!(exit.ticks, 2);

        let mut callbacks = FakeCallbacks {
            signal_at: Some(1),
            signal: RuntimeLoopSignal::Upgrade(MachineUpgradeCommand {
                id: "upgrade-1".to_string(),
                target_version: "v0.4.0".to_string(),
            }),
            ..FakeCallbacks::default()
        };

        let exit = run_runtime_loop(
            &mut callbacks,
            RuntimeLoopOptions {
                max_ticks: Some(5),
                tick_interval: Duration::from_secs(0),
                ..RuntimeLoopOptions::default()
            },
        )
        .unwrap();

        assert_eq!(exit.ticks, 1);
        assert_eq!(
            exit.reason,
            RuntimeLoopExitReason::Signal(RuntimeLoopSignal::Upgrade(MachineUpgradeCommand {
                id: "upgrade-1".to_string(),
                target_version: "v0.4.0".to_string(),
            }))
        );
    }

    struct FakeCallbacks {
        ticks: Vec<RuntimeTickOptions>,
        refreshes: usize,
        signal_at: Option<usize>,
        signal: RuntimeLoopSignal,
    }

    impl Default for FakeCallbacks {
        fn default() -> Self {
            Self {
                ticks: Vec::new(),
                refreshes: 0,
                signal_at: None,
                signal: RuntimeLoopSignal::Continue,
            }
        }
    }

    impl RuntimeLoopCallbacks for FakeCallbacks {
        fn refresh_users(&mut self) -> Result<BTreeMap<String, Vec<UserInfo>>, String> {
            self.refreshes += 1;
            let mut users = BTreeMap::new();
            users.insert(
                "node-a".to_string(),
                vec![UserInfo {
                    id: self.refreshes as u32,
                    uuid: format!("user-{}", self.refreshes),
                    speed_limit: 0,
                    device_limit: 0,
                }],
            );
            Ok(users)
        }

        fn run_tick(&mut self, options: RuntimeTickOptions) -> Result<RuntimeLoopSignal, String> {
            self.ticks.push(options);
            if self.signal_at == Some(self.ticks.len()) {
                return Ok(self.signal.clone());
            }
            Ok(RuntimeLoopSignal::Continue)
        }

        fn sleep(&mut self, _duration: Duration) -> Result<(), String> {
            Ok(())
        }
    }
}
