use bit_field::BitField;
use core::marker::PhantomData;

use crate::{HyperCraftHal, HostPhysAddr, GuestPhysAddr};
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
