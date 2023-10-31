use x86::{bits64::vmx, vmx::VmFail};
use x86_64::registers::control::{Cr0, Cr4, Cr4Flags};

use crate::{HyperCraftHal, HyperError, HyperResult};
use crate::arch::msr::{Msr, MsrReadWrite, VmxBasic, FeatureControl, FeatureControlFlags};
use super::detect::has_hardware_support;
use super::region::VmxRegion;

/// State per vmx physical cpu.
pub struct VmxPerCpuState<H: HyperCraftHal> {
    pub(super) vmcs_revision_id: u32,
    vmx_region: VmxRegion<H>,
}

impl<H: HyperCraftHal> VmxPerCpuState<H> {
    pub const fn new() -> Self {
        Self {
            vmcs_revision_id: 0,
            vmx_region: unsafe { VmxRegion::uninit() },
        }
    }

    pub fn is_enabled(&self) -> bool {
        Cr4::read().contains(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS)
    }

    pub fn hardware_enable(&mut self) -> HyperResult {
        if !has_hardware_support() {
            return Err(HyperError::NotSupported);
        }
        if self.is_enabled() {
            return Err(HyperError::Disabled);
        }

        // Enable VMXON, if required.
        let ctrl = FeatureControl::read();
        let locked = ctrl.contains(FeatureControlFlags::LOCKED);
        let vmxon_outside = ctrl.contains(FeatureControlFlags::VMXON_ENABLED_OUTSIDE_SMX);
        if !locked {
            FeatureControl::write(
                ctrl | FeatureControlFlags::LOCKED | FeatureControlFlags::VMXON_ENABLED_OUTSIDE_SMX,
            )
        } else if !vmxon_outside {
            return Err(HyperError::NotSupported);
        }

        // Check control registers are in a VMX-friendly state. (SDM Vol. 3C, Appendix A.7, A.8)
        macro_rules! cr_is_valid {
            ($value: expr, $crx: ident) => {{
                use Msr::*;
                let value = $value;
                let fixed0 = concat_idents!(IA32_VMX_, $crx, _FIXED0).read();
                let fixed1 = concat_idents!(IA32_VMX_, $crx, _FIXED1).read();
                (!fixed0 | value != 0) && (fixed1 | !value != 0)
            }};
        }
        if !cr_is_valid!(Cr0::read().bits(), CR0) {
            return Err(HyperError::BadState);
        }
        if !cr_is_valid!(Cr4::read().bits(), CR4) {
            return Err(HyperError::BadState);
        }

        // Get VMCS revision identifier in IA32_VMX_BASIC MSR.
        let vmx_basic = VmxBasic::read();
        if vmx_basic.region_size as usize != H::PAGE_SIZE {
            return Err(HyperError::NotSupported);
        }
        if vmx_basic.mem_type != VmxBasic::VMX_MEMORY_TYPE_WRITE_BACK {
            return Err(HyperError::NotSupported);
        }
        if vmx_basic.is_32bit_address {
            return Err(HyperError::NotSupported);
        }
        if !vmx_basic.io_exit_info {
            return Err(HyperError::NotSupported);
        }
        if !vmx_basic.vmx_flex_controls {
            return Err(HyperError::NotSupported);
        }
        self.vmcs_revision_id = vmx_basic.revision_id;
        self.vmx_region = VmxRegion::new(vmx_basic.revision_id, false)?;

        unsafe {
            // Enable VMX using the VMXE bit.
            Cr4::write(Cr4::read() | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS);
            // Execute VMXON.
            vmx::vmxon(self.vmx_region.phys_addr() as _)?;
        }

        Ok(())
    }

    pub fn hardware_disable(&mut self) -> HyperResult {
        if !self.is_enabled() {
            return Err(HyperError::BadState);
        }

        unsafe {
            // Execute VMXOFF.
            vmx::vmxoff()?;
            // Remove VMXE bit in CR4.
            Cr4::update(|cr4| cr4.remove(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS));
        };

        self.vmx_region = unsafe { VmxRegion::uninit() };
        Ok(())
    }
}

impl From<VmFail> for HyperError {
    fn from(_: VmFail) -> Self {
        HyperError::BadState
        /* TODO: add desc to HyperError
        match err {
            VmFail::VmFailValid => Err(BadState, vmcs::instruction_error().as_str()),
            _ => Err(BadState, format_args!("VMX instruction failed: {:?}", err)),
        } */
    }
}