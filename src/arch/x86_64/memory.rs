use bitflags;

use crate::memory::GuestPhysAddr;

bitflags::bitflags! {
    /// Permission and type of a guest physical memory region.
    pub struct MemFlags: u64 {
        const READ          = 1 << 0;
        const WRITE         = 1 << 1;
        const EXECUTE       = 1 << 2;
        const DEVICE        = 1 << 3;
    }
}

/// Information about nested page faults.
#[derive(Debug)]
pub struct NestedPageFaultInfo {
    /// Access type that caused the nested page fault.
    pub access_flags: MemFlags,
    /// Guest physical address that caused the nested page fault.
    pub fault_guest_paddr: GuestPhysAddr,
}
