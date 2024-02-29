use bit_field::BitField;
use core::marker::PhantomData;

use crate::{HyperCraftHal, HostPhysAddr, HostVirtAddr, GuestPhysAddr};
use crate::{HyperResult, HyperError};
use crate::arch::memory::PhysFrame;

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

    pub fn virt_addr(&self) -> HostVirtAddr {
        self.frame.as_mut_ptr() as usize
    }
}


#[derive(Debug)]
pub struct MsrBitmap<H: HyperCraftHal> {
    frame: PhysFrame<H>,
}

impl<H: HyperCraftHal> MsrBitmap<H> {
    pub fn passthrough_all() -> HyperResult<Self> {
        Ok(Self {
            frame: PhysFrame::alloc_zero()?,
        })
    }

    #[allow(unused)]
    pub fn intercept_all() -> HyperResult<Self> {
        let mut frame = PhysFrame::alloc()?;
        frame.fill(u8::MAX);
        Ok(Self { frame })
    }

    pub fn phys_addr(&self) -> HostPhysAddr {
        self.frame.start_paddr()
    }

    fn set_intercept(&mut self, msr: u32, is_write: bool, intercept: bool) {
        let offset = if msr <= 0x1fff {
            if !is_write {
                0 // Read bitmap for low MSRs (0x0000_0000..0x0000_1FFF)
            } else {
                2 // Write bitmap for low MSRs (0x0000_0000..0x0000_1FFF)
            }
        } else if (0xc000_0000..=0xc000_1fff).contains(&msr) {
            if !is_write {
                1 // Read bitmap for high MSRs (0xC000_0000..0xC000_1FFF)
            } else {
                3 // Write bitmap for high MSRs (0xC000_0000..0xC000_1FFF)
            }
        } else {
            unreachable!()
        } * 1024;
        let bitmap =
            unsafe { core::slice::from_raw_parts_mut(self.frame.as_mut_ptr().add(offset), 1024) };
        let msr = msr & 0x1fff;
        let byte = (msr / 8) as usize;
        let bits = msr % 8;
        if intercept {
            bitmap[byte] |= 1 << bits;
        } else {
            bitmap[byte] &= !(1 << bits);
        }
    }

    pub fn set_read_intercept(&mut self, msr: u32, intercept: bool) {
        self.set_intercept(msr, false, intercept);
    }

    pub fn set_write_intercept(&mut self, msr: u32, intercept: bool) {
        self.set_intercept(msr, true, intercept);
    }
}
