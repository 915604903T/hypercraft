use bit_field::BitField;
use bitflags::bitflags;
use x86::msr::{rdmsr, wrmsr};

/// X86 model-specific registers. (SDM Vol. 4)
#[repr(u32)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types, dead_code)]
pub enum Msr {
    IA32_FEATURE_CONTROL = 0x3a,

    IA32_SYSENTER_CS = 0x174,
    IA32_SYSENTER_ESP = 0x175,
    IA32_SYSENTER_EIP = 0x176,
    
    IA32_PAT = 0x277,
    IA32_MTRR_DEF_TYPE = 0x2ff,

    IA32_VMX_BASIC = 0x480,
    IA32_VMX_PINBASED_CTLS = 0x481,
    IA32_VMX_PROCBASED_CTLS = 0x482,
    IA32_VMX_EXIT_CTLS = 0x483,
    IA32_VMX_ENTRY_CTLS = 0x484,
    IA32_VMX_MISC = 0x485,
    IA32_VMX_CR0_FIXED0 = 0x486,
    IA32_VMX_CR0_FIXED1 = 0x487,
    IA32_VMX_CR4_FIXED0 = 0x488,
    IA32_VMX_CR4_FIXED1 = 0x489,
    IA32_VMX_PROCBASED_CTLS2 = 0x48b,
    IA32_VMX_EPT_VPID_CAP = 0x48c,
    IA32_VMX_TRUE_PINBASED_CTLS = 0x48d,
    IA32_VMX_TRUE_PROCBASED_CTLS = 0x48e,
    IA32_VMX_TRUE_EXIT_CTLS = 0x48f,
    IA32_VMX_TRUE_ENTRY_CTLS = 0x490,

    IA32_XSS = 0xda0,

    IA32_EFER = 0xc000_0080,
    IA32_STAR = 0xc000_0081,
    IA32_LSTAR = 0xc000_0082,
    IA32_CSTAR = 0xc000_0083,
    IA32_FMASK = 0xc000_0084,

    IA32_FS_BASE = 0xc000_0100,
    IA32_GS_BASE = 0xc000_0101,
    IA32_KERNEL_GSBASE = 0xc000_0102,
}

impl Msr {
    /// Read 64 bits msr register.
    #[inline(always)]
    pub fn read(self) -> u64 {
        unsafe { rdmsr(self as _) }
    }

    /// Write 64 bits to msr register.
    ///
    /// # Safety
    ///
    /// The caller must ensure that this write operation has no unsafe side
    /// effects.
    #[inline(always)]
    pub unsafe fn write(self, value: u64) {
        wrmsr(self as _, value)
    }
}

pub(super) trait MsrReadWrite {
    const MSR: Msr;

    fn read_raw() -> u64 {
        Self::MSR.read()
    }

    unsafe fn write_raw(flags: u64) {
        Self::MSR.write(flags);
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


/// Reporting Register of Basic VMX Capabilities. (SDM Vol. 3D, Appendix A.1)
#[derive(Debug)]
pub struct VmxBasic {
    /// The 31-bit VMCS revision identifier used by the processor.
    pub revision_id: u32,
    /// The number of bytes that software should allocate for the VMXON region
    /// and any VMCS region.
    pub region_size: u16,
    /// The width of the physical addresses that may be used for the VMXON
    /// region, each VMCS, and data structures referenced by pointers in a VMCS.
    pub is_32bit_address: bool,
    /// The memory type that should be used for the VMCS, for data structures
    /// referenced by pointers in the VMCS.
    pub mem_type: u8,
    /// The processor reports information in the VM-exit instruction-information
    /// field on VM exits due to execution of the INS and OUTS instructions.
    pub io_exit_info: bool,
    /// If any VMX controls that default to 1 may be cleared to 0.
    pub vmx_flex_controls: bool,
}

impl MsrReadWrite for VmxBasic {
    const MSR: Msr = Msr::IA32_VMX_BASIC;
}

impl VmxBasic {
    pub const VMX_MEMORY_TYPE_WRITE_BACK: u8 = 6;

    /// Read the current IA32_VMX_BASIC flags.
    pub fn read() -> Self {
        let msr = Self::read_raw();
        Self {
            revision_id: msr.get_bits(0..31) as u32,
            region_size: msr.get_bits(32..45) as u16,
            is_32bit_address: msr.get_bit(48),
            mem_type: msr.get_bits(50..54) as u8,
            io_exit_info: msr.get_bit(54),
            vmx_flex_controls: msr.get_bit(55),
        }
    }
}
