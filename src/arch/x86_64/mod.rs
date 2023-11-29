#[macro_use]
mod regs;

// Codes in this module come mainly from https://github.com/rcore-os/RVM-Tutorial

mod device;
mod ept;
mod lapic;
mod memory;
mod msr;
mod vmx;
mod percpu;

use crate::{GuestPageTableTrait, HyperCraftHal, VmCpus, HyperResult, vcpus, HyperError};
use bit_set::BitSet;
use page_table::PagingIf;

/// Initialize the hypervisor runtime.
pub fn init_hv_runtime() {
    if !vmx::has_hardware_support() {
        panic!("VMX not supported");
    }
}

/// Nested page table define.
pub use ept::ExtendedPageTable as NestedPageTable;

/// VCpu define.
pub use vmx::VmxVcpu as VCpu;
pub use percpu::PerCpu;
pub use vmx::{VmxExitReason, VmxExitInfo};

pub use device::{Devices, PortIoDevice};

////// Following are things to be implemented

/// VM define.
pub struct VM<H: HyperCraftHal> {
    vcpus: VmCpus<H>,
    vcpu_bond: BitSet,
}

impl<H: HyperCraftHal> VM<H> {
    /// Create a new [`VM`].
    pub fn new(vcpus: VmCpus<H>) -> Self {
        Self { vcpus, vcpu_bond: BitSet::new() }
    }

    /// Bind the specified [`VCpu`] to current physical processor.
    pub fn bind_vcpu(&mut self, vcpu_id: usize) -> HyperResult<&mut VCpu<H>> {
        if self.vcpu_bond.contains(vcpu_id) {
            Err(HyperError::InvalidParam)
        } else {
            match self.vcpus.get_vcpu(vcpu_id) {
                Ok(vcpu) => {
                    self.vcpu_bond.insert(vcpu_id);
                    vcpu.bind_to_current_processor()?;
                    Ok(vcpu)
                },
                e @ Err(_) => e,
            }
        }
    }

    /// Run a specified [`VCpu`] on current logical vcpu.
    pub fn run_vcpu(&mut self, vcpu_id: usize) -> ! {
        self.vcpus.get_vcpu(vcpu_id).unwrap().run();
    }

    /// Unbind the specified [`VCpu`] gotten by [`VM<H>::bind_vcpu`].
    pub fn unbind_vcpu(&mut self, vcpu_id: usize) -> HyperResult {
        if self.vcpu_bond.contains(vcpu_id) {
            match self.vcpus.get_vcpu(vcpu_id) {
                Ok(vcpu) => {
                    self.vcpu_bond.remove(vcpu_id);
                    vcpu.unbind_from_current_processor()?;
                    Ok(())
                },
                Err(e) => Err(e),
            }
        } else {
            Err(HyperError::InvalidParam)
        }
    }
}

/// VM exit information.
pub struct VmExitInfo {}

/// General purpose register index.
pub enum GprIndex {}

/// Hypercall message.
pub enum HyperCallMsg {}

