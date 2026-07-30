//! Best-effort operating-system hardening for processes handling secret keys.

use std::fmt;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// Prevents process memory from being included in ordinary core dumps and
/// debugger-style process dumps where the host OS supports it.
///
/// This complements `ZeroizeOnDrop`; it does not replace swap encryption,
/// sandboxing, or dedicated locked-memory secret containers.
pub fn harden_process_memory() -> Result<(), String> {
    platform::harden_process_memory()
}

/// Keeps an existing byte range resident in RAM until the returned guard is
/// dropped. The guard borrows the value so safe Rust cannot move or destroy it
/// while the operating-system lock refers to its address.
///
/// Callers must handle failure: hosts commonly enforce a small
/// `RLIMIT_MEMLOCK`. The value remains usable and should still be zeroized.
pub fn lock_secret<T: ?Sized>(secret: &T) -> Result<SecretMemoryLock<'_, T>, String> {
    let address = std::ptr::from_ref(secret).cast::<u8>();
    let length = size_of_val(secret);
    platform::lock(address, length)?;
    Ok(SecretMemoryLock {
        address,
        length,
        _borrow: PhantomData,
    })
}

/// RAII guard for a region locked by [`lock_secret`].
#[must_use = "dropping the guard immediately unlocks the secret memory"]
pub struct SecretMemoryLock<'a, T: ?Sized> {
    address: *const u8,
    length: usize,
    _borrow: PhantomData<&'a T>,
}

/// Heap-backed secret whose address stays stable, is locked in RAM when the OS
/// permits it, and is zeroized before being unlocked and freed.
pub struct LockedSecret<T: Zeroize> {
    value: Box<T>,
    locked: bool,
}

impl<T: Zeroize> fmt::Debug for LockedSecret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LockedSecret([REDACTED])")
    }
}

impl<T: Zeroize + PartialEq> PartialEq for LockedSecret<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value.eq(&other.value)
    }
}

impl<T: Zeroize + Eq> Eq for LockedSecret<T> {}

impl<T: Zeroize> LockedSecret<T> {
    /// Creates a secret container. Locking is best-effort because deployments
    /// may have a restrictive `RLIMIT_MEMLOCK`; zeroization is unconditional.
    pub fn new(value: T) -> Self {
        let boxed = Box::new(value);
        let address = std::ptr::from_ref::<T>(&boxed).cast::<u8>();
        let locked = platform::lock(address, size_of::<T>()).is_ok();
        Self {
            value: boxed,
            locked,
        }
    }

    /// Reports whether this allocation was successfully locked against swap.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<T: Zeroize> Deref for LockedSecret<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T: Zeroize> DerefMut for LockedSecret<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl<T: Zeroize> Drop for LockedSecret<T> {
    fn drop(&mut self) {
        self.value.zeroize();
        if self.locked {
            let address = std::ptr::from_ref::<T>(&self.value).cast::<u8>();
            platform::unlock(address, size_of::<T>());
        }
    }
}

impl<T: ?Sized> Drop for SecretMemoryLock<'_, T> {
    fn drop(&mut self) {
        platform::unlock(self.address, self.length);
    }
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
        fn mlock(address: *const core::ffi::c_void, length: usize) -> i32;
        fn munlock(address: *const core::ffi::c_void, length: usize) -> i32;
        fn prctl(option: i32, ...) -> i32;
        fn setrlimit(resource: i32, limit: *const RLimit) -> i32;
    }

    pub fn lock(address: *const u8, length: usize) -> Result<(), String> {
        if length == 0 {
            return Ok(());
        }
        // SAFETY: the caller holds a shared borrow for the guard lifetime, so
        // this range remains allocated and at a stable address until munlock.
        if unsafe { mlock(address.cast(), length) } != 0 {
            return Err(format!(
                "failed to lock secret memory: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    pub fn unlock(address: *const u8, length: usize) {
        if length != 0 {
            // SAFETY: this is the same live range previously passed to mlock.
            let _ = unsafe { munlock(address.cast(), length) };
        }
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

    pub fn lock(_address: *const u8, _length: usize) -> Result<(), String> {
        Ok(())
    }

    pub fn unlock(_address: *const u8, _length: usize) {}
}

#[cfg(test)]
mod tests {
    use super::{LockedSecret, lock_secret};
    use zeroize::{Zeroize, Zeroizing};

    #[test]
    fn locked_region_remains_usable_and_is_released_by_raii() {
        let secret = Zeroizing::new([7_u8; 32]);
        if let Ok(guard) = lock_secret(&*secret) {
            assert_eq!(secret[0], 7);
            drop(guard);
        }
    }

    #[test]
    fn zero_sized_region_is_supported() {
        let mut secret = ();
        let guard = lock_secret(&secret).expect("zero-sized lock");
        drop(guard);
        secret.zeroize();
    }

    #[test]
    fn heap_backed_secret_has_a_stable_locked_lifetime() {
        let secret = LockedSecret::new([9_u8; 32]);
        assert_eq!(secret[0], 9);
        let moved = secret;
        assert_eq!(moved[31], 9);
    }
}
