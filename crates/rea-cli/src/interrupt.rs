//! Translating SIGINT and SIGTERM into cancellation and conventional exit codes.
//!
//! Upstream reference: `withCommandCancellation` in
//! `upstream:src/cli/commandCancellation.ts`.

use rea_domain::cancellation::CancellationSignal;

/// Exit code after SIGINT.
pub const SIGINT_EXIT_CODE: u8 = 130;
/// Exit code after SIGTERM.
pub const SIGTERM_EXIT_CODE: u8 = 143;

/// Interrupt handlers for one command, removed on drop.
#[derive(Debug)]
pub struct Interrupts {
    signal: CancellationSignal,
    #[cfg(unix)]
    watch: unix::Watch,
}

impl Interrupts {
    /// Cancel `signal()` when the process is interrupted or terminated.
    ///
    /// Handler registration can fail only when the host forbids the signal;
    /// the command then simply cannot be cancelled by it.
    pub fn install() -> Self {
        #[cfg(unix)]
        {
            let watch = unix::Watch::install();
            Self {
                signal: watch.signal(),
                watch,
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                signal: CancellationSignal::new(),
            }
        }
    }

    /// The cancellation every interrupt sets.
    pub fn signal(&self) -> &CancellationSignal {
        &self.signal
    }

    /// The conventional exit code of the interrupt received, if any.
    pub fn exit_code(&self) -> Option<u8> {
        #[cfg(unix)]
        {
            self.watch.exit_code()
        }
        #[cfg(not(unix))]
        {
            None
        }
    }
}

#[cfg(unix)]
mod unix {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use rea_domain::cancellation::CancellationSignal;
    use signal_hook::SigId;
    use signal_hook::consts::{SIGINT, SIGTERM};
    use signal_hook::flag;

    use super::{SIGINT_EXIT_CODE, SIGTERM_EXIT_CODE};

    #[derive(Debug)]
    pub struct Watch {
        cancelled: Arc<AtomicBool>,
        interrupted: Arc<AtomicBool>,
        terminated: Arc<AtomicBool>,
        registrations: Vec<SigId>,
    }

    impl Watch {
        pub fn install() -> Self {
            let cancelled = Arc::new(AtomicBool::new(false));
            let interrupted = Arc::new(AtomicBool::new(false));
            let terminated = Arc::new(AtomicBool::new(false));
            let registrations = [
                (SIGINT, &cancelled),
                (SIGINT, &interrupted),
                (SIGTERM, &cancelled),
                (SIGTERM, &terminated),
            ]
            .into_iter()
            .filter_map(|(number, target)| flag::register(number, Arc::clone(target)).ok())
            .collect();
            Self {
                cancelled,
                interrupted,
                terminated,
                registrations,
            }
        }

        pub fn signal(&self) -> CancellationSignal {
            CancellationSignal::from_flag(Arc::clone(&self.cancelled))
        }

        pub fn exit_code(&self) -> Option<u8> {
            if self.interrupted.load(Ordering::Acquire) {
                Some(SIGINT_EXIT_CODE)
            } else if self.terminated.load(Ordering::Acquire) {
                Some(SIGTERM_EXIT_CODE)
            } else {
                None
            }
        }
    }

    impl Drop for Watch {
        fn drop(&mut self) {
            for registration in self.registrations.drain(..) {
                signal_hook::low_level::unregister(registration);
            }
        }
    }
}
