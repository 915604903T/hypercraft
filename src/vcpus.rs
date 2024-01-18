use alloc::boxed::Box;
use arrayvec::ArrayVec;
use spin::Once;
use vm_config::VmConfigEntry;

use crate::arch::{VCpu, VM};
use crate::hal::PerCpuDevices;
use crate::{GuestPageTableTrait, HyperCraftHal, HyperError, HyperResult,};


/// The maximum number of CPUs we can support.
pub const MAX_CPUS: usize = 8;

pub const VM_CPUS_MAX: usize = MAX_CPUS;

/// The set of vCPUs in a VM.
#[derive(Default)]
pub struct VmCpus<H: HyperCraftHal, PD: PerCpuDevices<H>> {
    inner: [Once<VCpu<H>>; VM_CPUS_MAX],
    device: [Once<PD>; VM_CPUS_MAX],
}

impl<H: HyperCraftHal, PD: PerCpuDevices<H>> VmCpus<H, PD> {
    /// Creates a new vCPU tracking structure.
    pub fn new() -> Self {
        Self {
            inner: [Once::INIT; VM_CPUS_MAX],
            device: [Once::INIT; VM_CPUS_MAX],
        }
    }

    /// Adds the given vCPU to the set of vCPUs.
    pub fn add_vcpu(&mut self, vcpu: VCpu<H>, config: VmConfigEntry) -> HyperResult<()> {
        let vcpu_id = vcpu.vcpu_id();
        let once_entry = self.inner.get(vcpu_id).ok_or(HyperError::BadState)?;

        let real_vcpu = once_entry.call_once(|| vcpu);
        let device_once_entry = self.device.get(vcpu_id).ok_or(HyperError::BadState)?;

        device_once_entry.call_once(|| PD::new(real_vcpu, config).unwrap());

        Ok(())
    }

    /// Returns a reference to the vCPU with `vcpu_id` if it exists.
    pub fn get_vcpu_and_device(&mut self, vcpu_id: usize) -> HyperResult<(&mut VCpu<H>, &mut PD)> {
        let vcpu = self
            .inner
            .get_mut(vcpu_id)
            .and_then(|once| once.get_mut())
            .ok_or(HyperError::NotFound)?;
        let device = self
            .device
            .get_mut(vcpu_id)
            .and_then(|once| once.get_mut())
            .ok_or(HyperError::NotFound)?;
        Ok((vcpu, device))
    }
}

// Safety: Each VCpu is wrapped with a Mutex to provide safe concurrent access to VCpu.
unsafe impl<H: HyperCraftHal, PD: PerCpuDevices<H>> Sync for VmCpus<H, PD> {}
unsafe impl<H: HyperCraftHal, PD: PerCpuDevices<H>> Send for VmCpus<H, PD> {}
