//! Best-effort operating-system hardening for wallet processes handling secrets.

pub fn harden_process_memory() -> Result<(), String> {
    platform::harden_process_memory()
}

#[cfg(unix)]
mod unix {
    use std::io;

    // RLIMIT_CORE is 4 on the Unix targets supported here (Linux, Apple, and
    // the BSD family).
    const RLIMIT_CORE: i32 = 4;

    #[cfg(target_pointer_width = "64")]
    type RLimitValue = u64;
    #[cfg(target_pointer_width = "32")]
    type RLimitValue = u32;

    #[repr(C)]
    struct RLimit {
        current: RLimitValue,
        maximum: RLimitValue,
    }

    unsafe extern "C" {
        fn setrlimit(resource: i32, limit: *const RLimit) -> i32;
    }

    pub fn disable_core_dumps() -> Result<(), String> {
        let no_core = RLimit {
            current: 0,
            maximum: 0,
        };
        // SAFETY: `no_core` matches the target's `struct rlimit` ABI and
        // remains alive for the duration of the call.
        if unsafe { setrlimit(RLIMIT_CORE, &no_core) } != 0 {
            return Err(format!(
                "failed to disable core dumps: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::io;

    const PR_SET_DUMPABLE: i32 = 4;

    unsafe extern "C" {
        fn prctl(option: i32, ...) -> i32;
    }

    pub fn harden_process_memory() -> Result<(), String> {
        super::unix::disable_core_dumps()?;
        // SAFETY: PR_SET_DUMPABLE consumes one integer argument.
        if unsafe { prctl(PR_SET_DUMPABLE, 0_i32) } != 0 {
            return Err(format!(
                "failed to mark process non-dumpable: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
mod platform {
    pub fn harden_process_memory() -> Result<(), String> {
        super::unix::disable_core_dumps()
    }
}

#[cfg(not(unix))]
mod platform {
    pub fn harden_process_memory() -> Result<(), String> {
        // Windows requires a separate process-mitigation implementation. Keep
        // startup portable while making the unsupported case explicit here.
        Ok(())
    }
}
