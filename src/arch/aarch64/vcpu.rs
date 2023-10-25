// Copyright (c) 2023 Beihang University, Huawei Technologies Co.,Ltd. All rights reserved.
// Rust-Shyper is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use core::arch::global_asm;
use spin::Mutex;
use core::marker::PhantomData;

// type ContextFrame = crate::arch::contextFrame::Aarch64ContextFrame;
use cortex_a::registers::*;
use tock_registers::interfaces::*;
 
use crate::arch::ContextFrame;
use crate::arch::context_frame::VmContext;
use crate::traits::ContextFrameTrait;
use crate::HyperCraftHal;
use crate::arch::hvc::run_guest_by_trap2el2;

/// (v)CPU register state that must be saved or restored when entering/exiting a VM or switching
/// between VMs.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct VmCpuRegisters {
    /// guest trap context
    pub guest_trap_context_regs: ContextFrame,
    /// arceos context
    pub save_for_os_context_regs: ContextFrame,
    /// virtual machine system regs setting
    pub vm_system_regs: VmContext,
}

impl VmCpuRegisters {
    /// create a default VmCpuRegisters
    pub fn default() -> VmCpuRegisters {
        VmCpuRegisters {
            guest_trap_context_regs: ContextFrame::default(),
            save_for_os_context_regs: ContextFrame::default(),
            vm_system_regs: VmContext::default(),
        }
    }
}

/// A virtual CPU within a guest
#[derive(Clone)]
pub struct VCpu<H:HyperCraftHal> {
    /// Vcpu id
    pub vcpu_id: usize,
    /// Vcpu context
    pub regs: VmCpuRegisters,
    // pub vcpu_ctx: ContextFrame,
    // pub vm_ctx: VmContext,
    // pub vm: Option<Vm>,
    // pub int_list: Vec<usize>,
    marker: PhantomData<H>,
}

impl <H:HyperCraftHal> VCpu<H> {
    /// Create a new vCPU
    pub fn new(id: usize) -> Self {
        Self {
            vcpu_id: id,
            regs: VmCpuRegisters::default(),
            // vcpu_ctx: ContextFrame::default(),
            // vm_ctx: VmContext::default(),
            // vm: None,
            // int_list: vec![],
            marker: PhantomData,
        }
    }

    /// Init Vcpu registers
    pub fn init(&mut self, kernel_entry_point: usize, device_tree_ipa: usize) {
        self.vcpu_arch_init(kernel_entry_point, device_tree_ipa);
        self.init_vm_context();
    }

    /// Get vcpu id
    pub fn vcpu_id(&self) -> usize {
        self.vcpu_id
    }

    /// Run this vcpu
    pub fn run(&self, vttbr_token: usize) -> ! {
        loop {  // because of elr_el2, it will not return to this?
            _ = run_guest_by_trap2el2(vttbr_token, self.vcpu_ctx_addr());
        }
    }
    
    /// Get vcpu whole context address
    pub fn vcpu_ctx_addr(&self) -> usize {
        &(self.regs) as *const _ as usize
    }
    
    /// Get vcpu trap context for guest or arceos
    pub fn vcpu_trap_ctx_addr(&self, if_guest: bool) -> usize {
        if if_guest {
            &(self.regs.guest_trap_context_regs) as *const _ as usize
        }else {
            &(self.regs.save_for_os_context_regs) as *const _ as usize
        }
    }

    /// Set exception return pc
    pub fn set_elr(&mut self, elr: usize) {
        self.regs.guest_trap_context_regs.set_exception_pc(elr);
    }

    /// Set general purpose register
    pub fn set_gpr(&mut self, idx: usize, val: usize) {
        self.regs.guest_trap_context_regs.set_gpr(idx, val);
    }

    /// Init guest context. Also set some el2 register value.
    fn init_vm_context(&mut self) {
        self.regs.vm_system_regs.cntvoff_el2 = 0;
        self.regs.vm_system_regs.sctlr_el1 = 0x30C50830;
        self.regs.vm_system_regs.cntkctl_el1 = 0;
        self.regs.vm_system_regs.pmcr_el0 = 0;
        // self.regs.vm_system_regs.vtcr_el2 = 0x8001355c;
        self.regs.vm_system_regs.vtcr_el2 = (VTCR_EL2::PS::PA_36B_64GB   //0b001 36 bits, 64GB.
                                          + VTCR_EL2::TG0::Granule4KB
                                          + VTCR_EL2::SH0::Inner
                                          + VTCR_EL2::ORGN0::NormalWBRAWA
                                          + VTCR_EL2::IRGN0::NormalWBRAWA
                                          + VTCR_EL2::SL0.val(0b01)
                                          + VTCR_EL2::T0SZ.val(64 - 36)).into();
        //self.regs.vm_system_regs.hcr_el2 = 0x80000001;  // Maybe we do not need smc setting? passthrough gic.
        self.regs.vm_system_regs.hcr_el2 = (HCR_EL2::VM::Enable
                                         + HCR_EL2::RW::EL1IsAarch64).into();
        let mut vmpidr = 0;
        vmpidr |= 1 << 31;
        vmpidr |= self.vcpu_id;
        self.regs.vm_system_regs.vmpidr_el2 = vmpidr as u64;
        
        // self.gic_ctx_reset(); // because of passthrough gic, do not need gic context anymore?
    }

    /// Init guest contextFrame
    fn vcpu_arch_init(&mut self, kernel_entry_point: usize, device_tree_ipa: usize) {
        self.set_gpr(0, device_tree_ipa);
        self.set_elr(kernel_entry_point);
        self.regs.guest_trap_context_regs.spsr =( SPSR_EL1::M::EL1h + 
                                            SPSR_EL1::I::Masked + 
                                            SPSR_EL1::F::Masked + 
                                            SPSR_EL1::A::Masked + 
                                            SPSR_EL1::D::Masked )
                                            .value;
    }

}
