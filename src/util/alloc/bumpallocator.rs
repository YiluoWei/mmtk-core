use crate::util::constants::DEFAULT_STRESS_FACTOR;
use std::sync::atomic::Ordering;
use super::allocator::{align_allocation_no_fill, fill_alignment_gap};
use crate::util::Address;

use crate::util::alloc::Allocator;

use crate::plan::Plan;
use crate::policy::space::Space;
use crate::util::conversions::bytes_to_pages;
use crate::util::OpaquePointer;
use crate::vm::{ActivePlan, VMBinding};

use crate::util::constants;
#[cfg(debug_assertions)]
use crate::util::constants::BYTES_IN_WORD;
use crate::util::conversions;
use crate::util::heap::layout::vm_layout_constants::BYTES_IN_CHUNK;
use crate::util::side_metadata::address_to_meta_address;
use crate::util::side_metadata::load_atomic;
#[cfg(target_pointer_width = "32")]
use crate::util::side_metadata::meta_bytes_per_chunk;
use crate::util::side_metadata::store_atomic;
use crate::util::side_metadata::try_map_metadata_space;
use crate::util::side_metadata::SideMetadataScope;
use crate::util::side_metadata::SideMetadataSpec;
#[cfg(target_pointer_width = "64")]
use crate::util::side_metadata::{metadata_address_range_size, LOCAL_SIDE_METADATA_BASE_ADDRESS};
use crate::util::ObjectReference;

use std::collections::HashSet;
use std::sync::RwLock;


const BYTES_IN_PAGE: usize = 1 << 12;
const BLOCK_SIZE: usize = 8 * BYTES_IN_PAGE;
const BLOCK_MASK: usize = BLOCK_SIZE - 1;

lazy_static! {
    pub static ref ACTIVE_CHUNKS: RwLock<HashSet<Address>> = RwLock::default();
}

pub(super) const ALLOC_METADATA_SPEC: SideMetadataSpec = SideMetadataSpec {
    scope: SideMetadataScope::PolicySpecific,
    offset: LOCAL_SIDE_METADATA_BASE_ADDRESS.as_usize(),
    log_num_of_bits: 0,
    log_min_obj_size: constants::LOG_MIN_OBJECT_SIZE as usize,
};

pub fn is_meta_space_mapped(address: Address) -> bool {
    let chunk_start = conversions::chunk_align_down(address);
    ACTIVE_CHUNKS.read().unwrap().contains(&chunk_start)
}

// pub fn map_meta_space_for_chunk(address: Address) {
pub fn map_meta_space_for_chunk() {
    // let chunk_start = conversions::chunk_align_down(address);
    // let mut active_chunks = ACTIVE_CHUNKS.write().unwrap();
    // if active_chunks.contains(&chunk_start) {
    //     return;
    // }
    // active_chunks.insert(chunk_start);
    let mmap_metadata_result = try_map_metadata_space(
        unsafe { Address::from_usize(0x20000000000) },
        0x4000_0000,
        &[],
        &[ALLOC_METADATA_SPEC],
    );
    debug_assert!(
        mmap_metadata_result.is_ok(),
        "mmap sidemetadata failed for chunk_start ({})",
        // chunk_start
    );
}

pub fn set_alloc_bit(object: Address) {
    // #[cfg(debug_assertions)]
    // if ASSERT_METADATA {
    //     // Need to make sure we atomically access the side metadata and the map.
    //     let mut lock = ALLOC_MAP.write().unwrap();
    //     store_atomic(ALLOC_METADATA_SPEC, object.to_address(), 1);
    //     lock.insert(object);
    //     return;
    // }
    trace!("set alloc bit for object 0x{}", object);
    store_atomic(ALLOC_METADATA_SPEC, object, 1);
}

#[repr(C)]
pub struct BumpAllocator<VM: VMBinding> {
    pub tls: OpaquePointer,
    cursor: Address,
    limit: Address,
    space: &'static dyn Space<VM>,
    plan: &'static dyn Plan<VM = VM>,
}

impl<VM: VMBinding> BumpAllocator<VM> {
    pub fn set_limit(&mut self, cursor: Address, limit: Address) {
        self.cursor = cursor;
        self.limit = limit;
    }

    pub fn reset(&mut self) {
        self.cursor = unsafe { Address::zero() };
        self.limit = unsafe { Address::zero() };
    }

    pub fn rebind(&mut self, space: &'static dyn Space<VM>) {
        self.reset();
        self.space = space;
    }
}

impl<VM: VMBinding> Allocator<VM> for BumpAllocator<VM> {
    fn get_space(&self) -> &'static dyn Space<VM> {
        self.space
    }
    fn get_plan(&self) -> &'static dyn Plan<VM = VM> {
        self.plan
    }

    fn alloc(&mut self, size: usize, align: usize, offset: isize) -> Address {
        trace!("alloc");
        let result = align_allocation_no_fill::<VM>(self.cursor, align, offset);
        let new_cursor = result + size;

        if new_cursor > self.limit {
            trace!("Thread local buffer used up, go to alloc slow path");
            let ret = self.alloc_slow(size, align, offset);
            ret
        } else {
            fill_alignment_gap::<VM>(self.cursor, result);
            self.cursor = new_cursor;
            trace!(
                "Bump allocation size: {}, result: {}, new_cursor: {}, limit: {}",
                size,
                result,
                self.cursor,
                self.limit
            );
            set_alloc_bit(result);
            result
        }
    }

    fn alloc_slow_once(&mut self, size: usize, align: usize, offset: isize) -> Address {
        trace!("alloc_slow");
        // TODO: internalLimit etc.
        let base = &self.plan.base();

        // if base.options.stress_factor == DEFAULT_STRESS_FACTOR
        //     && base.options.analysis_factor == DEFAULT_STRESS_FACTOR
        if true
        {
            let ret = self.acquire_block(size, align, offset, false);
            ret
        } else {
            self.alloc_slow_once_stress_test(size, align, offset)
        }
    }

    fn get_tls(&self) -> OpaquePointer {
        self.tls
    }
}

impl<VM: VMBinding> BumpAllocator<VM> {
    pub fn new(
        tls: OpaquePointer,
        space: &'static dyn Space<VM>,
        plan: &'static dyn Plan<VM = VM>,
    ) -> Self {
        // map_meta_space_for_chunk();
        BumpAllocator {
            tls,
            cursor: unsafe { Address::zero() },
            limit: unsafe { Address::zero() },
            space,
            plan,
        }
    }

    // Slow path for allocation if the stress test flag has been enabled. It works
    // by manipulating the limit to be below the cursor always.
    // Performs three kinds of allocations: (i) if the hard limit has been met;
    // (ii) the bump pointer semantics from the fastpath; and (iii) if the stress
    // factor has been crossed.
    fn alloc_slow_once_stress_test(&mut self, size: usize, align: usize, offset: isize) -> Address {
        trace!("alloc_slow stress_test");
        let result = align_allocation_no_fill::<VM>(self.cursor, align, offset);
        let new_cursor = result + size;

        // For stress test, limit is [0, block_size) to artificially make the
        // check in the fastpath (alloc()) fail. The real limit is recovered by
        // adding it to the current cursor.
        if new_cursor > self.cursor + self.limit.as_usize() {
            self.acquire_block(size, align, offset, true)
        } else {
            let base = &self.plan.base();
            let is_mutator =
                unsafe { VM::VMActivePlan::is_mutator(self.tls) } && self.plan.is_initialized();

            if is_mutator
                && base.allocation_bytes.load(Ordering::SeqCst) > base.options.stress_factor
            {
                trace!(
                    "Stress GC: allocation_bytes = {} more than stress_factor = {}",
                    base.allocation_bytes.load(Ordering::Relaxed),
                    base.options.stress_factor
                );
                return self.acquire_block(size, align, offset, true);
            }

            // This is the allocation hook for the analysis trait. If you want to call
            // an analysis counter specific allocation hook, then here is the place to do so
            #[cfg(feature = "analysis")]
            if is_mutator
                && base.allocation_bytes.load(Ordering::SeqCst) > base.options.analysis_factor
            {
                trace!(
                    "Analysis: allocation_bytes = {} more than analysis_factor = {}",
                    base.allocation_bytes.load(Ordering::Relaxed),
                    base.options.analysis_factor
                );

                base.analysis_manager.alloc_hook(size, align, offset);
            }

            fill_alignment_gap::<VM>(self.cursor, result);
            self.limit -= new_cursor - self.cursor;
            self.cursor = new_cursor;
            trace!(
                "alloc_slow: Bump allocation size: {}, result: {}, new_cursor: {}, limit: {}",
                size,
                result,
                self.cursor,
                self.limit
            );
            result
        }
    }

    #[inline]
    fn acquire_block(
        &mut self,
        size: usize,
        align: usize,
        offset: isize,
        stress_test: bool,
    ) -> Address {
        let block_size = (size + BLOCK_MASK) & (!BLOCK_MASK);
        let acquired_start = self.space.acquire(self.tls, bytes_to_pages(block_size));
        if acquired_start.is_zero() {
            trace!("Failed to acquire a new block");
            acquired_start
        } else {
            trace!(
                "Acquired a new block of size {} with start address {}",
                block_size,
                acquired_start
            );
            // map_meta_space_for_chunk(acquired_start);
            if !stress_test {
                self.set_limit(acquired_start, acquired_start + block_size);
            } else {
                // For a stress test, we artificially make the fastpath fail by
                // manipulating the limit as below.
                // The assumption here is that we use an address range such that
                // cursor > block_size always.
                self.set_limit(acquired_start, unsafe { Address::from_usize(block_size) });
            }
            self.alloc(size, align, offset)
        }
    }
}
