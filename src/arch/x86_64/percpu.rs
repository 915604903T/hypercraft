use crate::{HyperCraftHal, HostPhysAddr, GuestPhysAddr};
use crate::{HyperResult, HyperError};
use crate::arch::vmx::VmxPerCpuState;

use super::VmxVcpu;

/// Host per-CPU states to run the guest. All methods must be called on the corresponding CPU.
pub struct PerCpu<H: HyperCraftHal> {
    cpu_id: usize,
    arch: VmxPerCpuState<H>,
}

impl<H: HyperCraftHal> PerCpu<H> {
    /// Create an uninitialized instance.
    pub fn new(cpu_id: usize) -> Self {
        Self {
            cpu_id: cpu_id,
            arch: VmxPerCpuState::new(),
        }
    }

    /// Whether the current CPU has hardware virtualization enabled.
    pub fn is_enabled(&self) -> bool {
        self.arch.is_enabled()
    }

    /// Enable hardware virtualization on the current CPU.
    pub fn hardware_enable(&mut self) -> HyperResult {
        self.arch.hardware_enable()
    }

    /// Disable hardware virtualization on the current CPU.
    pub fn hardware_disable(&mut self) -> HyperResult {
        self.arch.hardware_disable()
    }

    /// Create a [`RvmVcpu`], set the entry point to `entry`, set the nested
    /// page table root to `npt_root`.
    pub fn create_vcpu(
        &self,
        entry: GuestPhysAddr,
        npt_root: HostPhysAddr,
    ) -> HyperResult<VmxVcpu<H>> {
        if !self.is_enabled() {
            Err(HyperError::BadState)
        } else {
            VmxVcpu::new(&self.arch, entry, npt_root)
        }
    }
}

impl<H: HyperCraftHal> Drop for PerCpu<H> {
    fn drop(&mut self) {
        if self.is_enabled() {
            self.hardware_disable().unwrap();
        }
    }
}

