//! Best-effort operating-system hardening for wallet processes handling secrets.

pub fn harden_process_memory() -> Result<(), String> {
    platform::harden_process_memory()
}

#[cfg(target_os = "linux")]
mod platform {
    use std::io;

    const PR_SET_DUMPABLE: i32 = 4;
    const RLIMIT_CORE: i32 = 4;

    #[repr(C)]
    struct RLimit {
        current: u64,
        maximum: u64,
    }

    unsafe extern "C" {
        fn prctl(option: i32, ...) -> i32;
        fn setrlimit(resource: i32, limit: *const RLimit) -> i32;
    }

    pub fn harden_process_memory() -> Result<(), String> {
        let no_core = RLimit {
            current: 0,
            maximum: 0,
        };
        // SAFETY: both calls use their documented Linux ABI and valid values.
        if unsafe { setrlimit(RLIMIT_CORE, &no_core) } != 0 {
            return Err(format!(
                "failed to disable core dumps: {}",
                io::Error::last_os_error()
            ));
        }
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

#[cfg(not(target_os = "linux"))]
mod platform {
    pub fn harden_process_memory() -> Result<(), String> {
        Ok(())
    }
}
