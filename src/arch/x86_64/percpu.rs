use bit_field::BitField;
use bitflags::bitflags;
use core::marker::PhantomData;
use x86::{bits64::vmx, vmx::VmFail};
use x86_64::registers::control::{Cr0, Cr4, Cr4Flags};

use crate::arch::detect;
use crate::arch::msr::{Msr, MsrReadWrite};
use crate::{HyperCraftHal, HostPhysAddr};
use crate::{HyperResult, HyperError};

/// A 4K-sized contiguous physical memory page, it will deallocate the page
/// automatically on drop.
#[derive(Debug)]
pub struct PhysFrame<H: HyperCraftHal> {
    start_paddr: HostPhysAddr,
    _phantom: PhantomData<H>,
}

impl<H: HyperCraftHal> PhysFrame<H> {
    pub fn alloc() -> HyperResult<Self> {
        let start_paddr = H::alloc_page()
            .ok_or_else(|| HyperError::NoMemory)?;
        assert_ne!(start_paddr, 0);
        Ok(Self {
            start_paddr,
            _phantom: PhantomData,
        })
    }

    pub fn alloc_zero() -> HyperResult<Self> {
        let mut f = Self::alloc()?;
        f.fill(0);
        Ok(f)
    }

    pub const unsafe fn uninit() -> Self {
        Self {
            start_paddr: 0,
            _phantom: PhantomData,
        }
    }

    pub fn start_paddr(&self) -> HostPhysAddr {
        self.start_paddr
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        H::phys_to_virt(self.start_paddr) as *mut u8
    }

    pub fn fill(&mut self, byte: u8) {
        unsafe { core::ptr::write_bytes(self.as_mut_ptr(), byte, H::PAGE_SIZE) }
    }
}

impl<H: HyperCraftHal> Drop for PhysFrame<H> {
    fn drop(&mut self) {
        if self.start_paddr > 0 {
            H::dealloc_page(self.start_paddr);
        }
    }
}

/// VMCS/VMXON region in 4K size. (SDM Vol. 3C, Section 24.2)
#[derive(Debug)]
pub struct VmxRegion<H: HyperCraftHal> {
    frame: PhysFrame<H>,
}

impl<H: HyperCraftHal> VmxRegion<H> {
    pub const unsafe fn uninit() -> Self {
        Self {
            frame: PhysFrame::uninit(),
        }
    }

    pub fn new(revision_id: u32, shadow_indicator: bool) -> HyperResult<Self> {
        let frame = PhysFrame::alloc_zero()?;
        unsafe {
            (*(frame.as_mut_ptr() as *mut u32))
                .set_bits(0..=30, revision_id)
                .set_bit(31, shadow_indicator);
        }
        Ok(Self { frame })
    }

    pub fn phys_addr(&self) -> HostPhysAddr {
        self.frame.start_paddr()
    }
}


bitflags! {
    /// IA32_FEATURE_CONTROL flags.
    pub struct FeatureControlFlags: u64 {
       /// Lock bit: when set, locks this MSR from being written. when clear,
       /// VMXON causes a #GP.
       const LOCKED = 1 << 0;
       /// Enable VMX inside SMX operation.
       const VMXON_ENABLED_INSIDE_SMX = 1 << 1;
       /// Enable VMX outside SMX operation.
       const VMXON_ENABLED_OUTSIDE_SMX = 1 << 2;
   }
}

/// Control Features in Intel 64 Processor. (SDM Vol. 3C, Section 23.7)
pub struct FeatureControl;

impl MsrReadWrite for FeatureControl {
    const MSR: Msr = Msr::IA32_FEATURE_CONTROL;
}

impl FeatureControl {
    /// Read the current IA32_FEATURE_CONTROL flags.
    pub fn read() -> FeatureControlFlags {
        FeatureControlFlags::from_bits_truncate(Self::read_raw())
    }

    /// Write IA32_FEATURE_CONTROL flags, preserving reserved values.
    pub fn write(flags: FeatureControlFlags) {
        let old_value = Self::read_raw();
        let reserved = old_value & !(FeatureControlFlags::all().bits());
        let new_value = reserved | flags.bits();
        unsafe { Self::write_raw(new_value) };
    }
}

pub struct VmxPerCpuState<H: HyperCraftHal> {
    vmcs_revision_id: u32,
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
        if !detect::has_hardware_support() {
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
            return rvm_err!(BadState, "host CR0 is not valid in VMX operation");
        }
        if !cr_is_valid!(Cr4::read().bits(), CR4) {
            return rvm_err!(BadState, "host CR4 is not valid in VMX operation");
        }

        // Get VMCS revision identifier in IA32_VMX_BASIC MSR.
        let vmx_basic = VmxBasic::read();
        if vmx_basic.region_size as usize != crate::mm::PAGE_SIZE {
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
        info!("[RVM] successed to turn on VMX.");

        Ok(())
    }

    pub fn hardware_disable(&mut self) -> RvmResult {
        if !self.is_enabled() {
            return rvm_err!(BadState, "VMX is not enabled");
        }

        unsafe {
            // Execute VMXOFF.
            vmx::vmxoff()?;
            // Remove VMXE bit in CR4.
            Cr4::update(|cr4| cr4.remove(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS));
        };
        info!("[RVM] successed to turn off VMX.");

        self.vmx_region = unsafe { VmxRegion::uninit() };
        Ok(())
    }
}

impl From<VmFail> for RvmError {
    fn from(err: VmFail) -> Self {
        match err {
            VmFail::VmFailValid => rvm_err_type!(BadState, vmcs::instruction_error().as_str()),
            _ => rvm_err_type!(BadState, format_args!("VMX instruction failed: {:?}", err)),
        }
    }
}

/// Host per-CPU states to run the guest. All methods must be called on the corresponding CPU.
pub struct RvmPerCpu<H: HyperCraftHal> {
    cpu_id: usize,
    arch: VmxPerCpuState<H>,
}

impl<H: HyperCraftHal> RvmPerCpu<H> {
    /// Create an uninitialized instance.
    pub fn new(cpu_id: usize) -> Self {
        Self {
            cpu_id: cpu_id,
            arch: ArchPerCpuState::new(),
        }
    }

    /// Whether the current CPU has hardware virtualization enabled.
    pub fn is_enabled(&self) -> bool {
        self.arch.is_enabled()
    }

    /// Enable hardware virtualization on the current CPU.
    pub fn hardware_enable(&mut self) -> RvmResult {
        self.arch.hardware_enable()
    }

    /// Disable hardware virtualization on the current CPU.
    pub fn hardware_disable(&mut self) -> RvmResult {
        self.arch.hardware_disable()
    }

    /// Create a [`RvmVcpu`], set the entry point to `entry`, set the nested
    /// page table root to `npt_root`.
    pub fn create_vcpu(
        &self,
        entry: GuestPhysAddr,
        npt_root: HostPhysAddr,
    ) -> RvmResult<RvmVcpu<H>> {
        if !self.is_enabled() {
            rvm_err!(BadState, "virtualization is not enabled")
        } else {
            RvmVcpu::new(&self.arch, entry, npt_root)
        }
    }
}

impl<H: RvmHal> Drop for RvmPerCpu<H> {
    fn drop(&mut self) {
        if self.is_enabled() {
            self.hardware_disable().unwrap();
        }
    }
}
