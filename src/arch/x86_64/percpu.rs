use crate::{HyperCraftHal, HostPhysAddr, GuestPhysAddr};
use crate::{HyperResult, HyperError};
use crate::arch::vmx::VmxPerCpuState;

use super::VCpu;
#[cfg(feature = "type1_5")]
use super::vmx::LinuxContext;

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
        match self.arch.hardware_enable() {
            Ok(_) => {
                info!("VMX enabled on cpu {}.", self.cpu_id);
                Ok(())
            },
            e @ Err(_) => {
                e
            }
        }
    }
    #[cfg(feature = "type1_5")]
    /// Enable type 1.5 hardware virtualization on the current CPU.
    pub fn hardware_enable_type1_5(&mut self, linux: &LinuxContext) -> HyperResult {
        match self.arch.hardware_enable_type1_5(linux) {
            Ok(_) => {
                info!("VMX enabled on cpu {}.", self.cpu_id);
                Ok(())
            },
            e @ Err(_) => {
                e
            }
        }
    }
    
    /// Disable hardware virtualization on the current CPU.
    pub fn hardware_disable(&mut self) -> HyperResult {
        match self.arch.hardware_disable() {
            Ok(_) => {
                info!("VMX disabled on cpu {}.", self.cpu_id);
                Ok(())
            },
            e @ Err(_) => {
                e
            }
        }
    }

    /// Get current vmcs revision id.
    pub fn vmcs_revision_id(&self) -> u32 {
        self.arch.vmcs_revision_id()
    }
}

impl<H: HyperCraftHal> Drop for PerCpu<H> {
    fn drop(&mut self) {
        if self.is_enabled() {
            self.hardware_disable().unwrap();
        }
    }
}

