use page_table_entry::x86_64::EPTEntry;
use page_table::{PagingMetaData, PageTable64};

pub struct ExtendedPageTableMetadata;

impl PagingMetaData for ExtendedPageTableMetadata {
    const LEVELS: usize = 4;
    const PA_MAX_BITS: usize = 52;
    const VA_MAX_BITS: usize = 52;
}

/// The VMX extended page table. (SDM Vol. 3C, Section 28.3)
pub type ExtendedPageTable<I> = PageTable64<ExtendedPageTableMetadata, EPTEntry, I>;
