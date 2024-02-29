use super::super::msr::Msr;
use x86::{segmentation, task};
use x86_64::registers::control::{Cr0, Cr0Flags, Cr3, Cr3Flags, Cr4, Cr4Flags};
// use x86_64::{addr::PhysAddr, structures::paging::PhysFrame, structures::DescriptorTablePointer};
use x86::dtables::{self, DescriptorTablePointer};
use super::segmentation::Segment;

const SAVED_LINUX_REGS: usize = 8;

#[derive(Debug)]
/// Linux Context for jailhouse pass
pub struct LinuxContext {
    /// The stack pointer of the linux context.
    pub rsp: u64,
    /// The instruction pointer of the linux context.
    pub rip: u64,

    /// General purpose registers r15
    pub r15: u64,
    /// General purpose registers r14
    pub r14: u64,
    /// General purpose registers r13
    pub r13: u64,
    /// General purpose registers r12
    pub r12: u64,
    /// rbx
    pub rbx: u64,
    /// rbp
    pub rbp: u64,

    /// Segment registers es
    pub es: Segment,
    /// Segment registers cs
    pub cs: Segment,
    /// Segment registers ss
    pub ss: Segment,
    /// Segment registers ds
    pub ds: Segment,
    /// Segment registers fs
    pub fs: Segment,
    /// Segment registers gs
    pub gs: Segment,
    /// Segment registers tss
    pub tss: Segment,
    /// Global Descriptor Table
    pub gdt: DescriptorTablePointer<u64>,
    /// Interrupt Descriptor Table
    pub idt: DescriptorTablePointer<u64>,

    /// Control Register 0
    pub cr0: Cr0Flags,
    /// Control Register 3
    pub cr3: u64,
    /// Control Register 4
    pub cr4: Cr4Flags,

    /// Extended Feature Enable Register
    pub efer: u64,
    /// legacy-mode SYSCALL Target Address Register
    pub star: u64,
    /// Long-Mode SYSCALL Target Address Register
    pub lstar: u64,
    /// Compatibility-Mode SYSCALL Target Address Register
    pub cstar: u64,
    /// SYSCALL Flag Mask
    pub fmask: u64,
    /// KERNEL_GS_BASE
    pub kernel_gsbase: u64,
    /// PAT
    pub pat: u64,
    /// Memory Type Range Registers
    pub mtrr_def_type: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
/// General purpose registers
pub struct GeneralRegisters {
    /// General purpose registers rax
    pub rax: u64,
    /// General purpose registers rcx
    pub rcx: u64,
    /// General purpose registers rdx
    pub rdx: u64,
    /// General purpose registers rbx
    pub rbx: u64,
    /// General purpose registers rsp
    _unused_rsp: u64,
    /// General purpose registers rbp
    pub rbp: u64,
    /// General purpose registers rsi
    pub rsi: u64,
    /// General purpose registers rdi
    pub rdi: u64,
    /// General purpose registers r8
    pub r8: u64,
    /// General purpose registers r9
    pub r9: u64,
    /// General purpose registers r10
    pub r10: u64,
    /// General purpose registers r11
    pub r11: u64,
    /// General purpose registers r12
    pub r12: u64,
    /// General purpose registers r13
    pub r13: u64,
    /// General purpose registers r14
    pub r14: u64,
    /// General purpose registers r15
    pub r15: u64,
}
/* 
macro_rules! save_regs_to_stack {
    () => {
        "
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8
        push rdi
        push rsi
        push rbp
        sub rsp, 8
        push rbx
        push rdx
        push rcx
        push rax"
    };
}
*/
macro_rules! restore_regs_from_stack {
    () => {
        "
        pop rax
        pop rcx
        pop rdx
        pop rbx
        add rsp, 8
        pop rbp
        pop rsi
        pop rdi
        pop r8
        pop r9
        pop r10
        pop r11
        pop r12
        pop r13
        pop r14
        pop r15"
    };
}

impl LinuxContext {
    /// Load linux callee-saved registers from the stack, and other system registers.
    pub fn load_from(linux_sp: usize) -> Self {
        let regs = unsafe { core::slice::from_raw_parts(linux_sp as *const u64, SAVED_LINUX_REGS) };
        // let gdt = GdtStruct::sgdt();

        let mut gdt = DescriptorTablePointer::<u64>::default();
        let mut idt = DescriptorTablePointer::<u64>::default();
        unsafe {
            dtables::sgdt(&mut gdt);
            dtables::sidt(&mut idt);
        } 
        let mut fs = Segment::from_selector(x86::segmentation::fs(), &gdt);
        let mut gs = Segment::from_selector(x86::segmentation::gs(), &gdt);
        fs.base = Msr::IA32_FS_BASE.read();
        gs.base = regs[0];

        Self {
            rsp: regs.as_ptr_range().end as _,
            r15: regs[1],
            r14: regs[2],
            r13: regs[3],
            r12: regs[4],
            rbx: regs[5],
            rbp: regs[6],
            rip: regs[7],
            es: Segment::from_selector(segmentation::es(), &gdt),
            cs: Segment::from_selector(segmentation::cs(), &gdt),
            ss: Segment::from_selector(segmentation::ss(), &gdt),
            ds: Segment::from_selector(segmentation::ds(), &gdt),
            fs,
            gs,
            tss: Segment::from_selector(unsafe { task::tr() }, &gdt),
            gdt,
            idt: idt,
            cr0: Cr0::read(),
            cr3: Cr3::read().0.start_address().as_u64(),
            cr4: Cr4::read(),
            efer: Msr::IA32_EFER.read(),
            star: Msr::IA32_STAR.read(),
            lstar: Msr::IA32_LSTAR.read(),
            cstar: Msr::IA32_CSTAR.read(),
            fmask: Msr::IA32_FMASK.read(),
            kernel_gsbase: Msr::IA32_KERNEL_GSBASE.read(),
            pat: Msr::IA32_PAT.read(),
            mtrr_def_type: Msr::IA32_MTRR_DEF_TYPE.read(),
        }
    }

    /// Restore linux general-purpose registers and stack, then return back to linux.
    pub fn return_to_linux(&self, guest_regs: &GeneralRegisters) -> ! {
        unsafe {
            Msr::IA32_GS_BASE.write(self.gs.base);
            core::arch::asm!(
                "mov rsp, {linux_rsp}",
                "push {linux_rip}",
                "mov rcx, rsp",
                "mov rsp, {guest_regs}",
                "mov [rsp + {guest_regs_size}], rcx",
                restore_regs_from_stack!(),
                "pop rsp",
                "ret",
                linux_rsp = in(reg) self.rsp,
                linux_rip = in(reg) self.rip,
                guest_regs = in(reg) guest_regs,
                guest_regs_size = const core::mem::size_of::<GeneralRegisters>(),
                options(noreturn),
            );
        }
    }
}
