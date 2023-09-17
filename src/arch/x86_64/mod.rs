#[macro_use]
mod regs;

// Codes in this module come mainly from https://github.com/rcore-os/RVM-Tutorial

// mod lapic;
mod memory;
mod msr;
mod vmx;
mod percpu;

use crate::{GuestPageTableTrait, HyperCraftHal};
use page_table::PagingIf;

pub use vmx::VmxVcpu;

/// Initialize the hypervisor runtime.
pub fn init_hv_runtime() {
    if !vmx::has_hardware_support() {
        panic!("VMX not supported");
    }
}

/// General purpose register index.
pub enum GprIndex {}

/// Hypercall message.
pub enum HyperCallMsg {}

/// Nested page table define.
pub struct NestedPageTable<I: PagingIf> {
    _marker: core::marker::PhantomData<I>,
}

/// VCpu define.
pub use vmx::VmxVcpu as VCpu;

impl<H: HyperCraftHal> VCpu<H> {
    /// Get the vcpu id.
    pub fn vcpu_id(&self) -> usize {
        todo!()
    }
}

/// VM define.
pub struct VM<H: HyperCraftHal> {
    _marker: core::marker::PhantomData<H>,
}

pub use percpu::PerCpu;

/// VM exit information.
pub struct VmExitInfo {}
