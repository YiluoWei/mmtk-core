//! Read/Write barrier implementations.
use crate::util::header_log_byte;
use crate::policy::space::Space;
use crate::scheduler::gc_work::*;
use crate::scheduler::WorkBucketStage;
use crate::util::side_metadata::*;
use crate::util::*;
use crate::MMTK;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Copy, Clone, Debug)]
pub enum BarrierSelector {
    NoBarrier,
    ObjectBarrier,
}

/// For field writes in HotSpot, we cannot always get the source object pointer and the field address
pub enum WriteTarget {
    Object(ObjectReference),
    Slot(Address),
}

pub trait Barrier: 'static + Send + Sync {
    fn flush(&mut self);
    fn post_write_barrier(&mut self, target: WriteTarget);
}

pub struct NoBarrier;

impl Barrier for NoBarrier {
    fn flush(&mut self) {}
    fn post_write_barrier(&mut self, _target: WriteTarget) {}
}

pub struct ObjectRememberingBarrier<E: ProcessEdgesWork, S: Space<E::VM>> {
    mmtk: &'static MMTK<E::VM>,
    _nursery: &'static S,
    modbuf: Vec<ObjectReference>,
    meta: SideMetadataSpec,
}

impl<E: ProcessEdgesWork, S: Space<E::VM>> ObjectRememberingBarrier<E, S> {
    #[allow(unused)]
    pub fn new(mmtk: &'static MMTK<E::VM>, nursery: &'static S, meta: SideMetadataSpec) -> Self {
        Self {
            mmtk,
            _nursery: nursery,
            modbuf: vec![],
            meta,
        }
    }

    #[inline(always)]
    fn add_to_buf(&mut self, obj: ObjectReference) {
        // if ENABLE_BARRIER_COUNTER {
        //     BARRIER_COUNTER.slow.fetch_add(1, atomic::Ordering::SeqCst);
        // }
        self.modbuf.push(obj);
        if self.modbuf.len() >= E::CAPACITY {
            self.flush();
        }
    }

    #[inline(always)]
    fn enqueue_node(&mut self, obj: ObjectReference) {
        if ENABLE_BARRIER_COUNTER {
            BARRIER_COUNTER.total.fetch_add(1, atomic::Ordering::SeqCst);
        }
        let header = header_log_byte::read_header(obj);
        let log_byte = (header & 0b1111_1111) as u8;
        if log_byte == header_log_byte::NO_LOCK {
            return;
        } 
        
        let lock_pattern = log_byte & header_log_byte::LOCK_MASK;
        if lock_pattern == header_log_byte::LIGHT_LOCK || lock_pattern == header_log_byte::HEAVY_LOCK {
            if ENABLE_BARRIER_COUNTER {
                BARRIER_COUNTER.locked.fetch_add(1, atomic::Ordering::SeqCst);
            }
            if header_log_byte::read_replaced_log_byte(header) == header_log_byte::NO_LOCK {
                if ENABLE_BARRIER_COUNTER {
                    BARRIER_COUNTER.locked_fast.fetch_add(1, atomic::Ordering::SeqCst);
                }
                return;
            } 
            if header_log_byte::compare_exchange_replaced_log_byte(header, header_log_byte::UNLOGGED_NO_LOCK, header_log_byte::NO_LOCK) {
                self.add_to_buf(obj);
            } else {
                // Spin here to make sure the object is logged, 
                // the CAS may fail because the header is replaced when unlocking the object,
                // in this case we can't just return
                // self.enqueue_node(obj);   
            }
        } else if lock_pattern == header_log_byte::NO_LOCK {
            if header_log_byte::compare_exchange_log_byte(obj, header_log_byte::UNLOGGED_NO_LOCK, header_log_byte::NO_LOCK) {                
                self.add_to_buf(obj);
            } else {
                // Spin here to make sure the object is logged, 
                // the CAS may fail because the header is replaced when locking the object,
                // in this case we can't just return
                // self.enqueue_node(obj);   
            }
        } else {
            panic!("Invalid lock pattern")
        }
    }
}

impl<E: ProcessEdgesWork, S: Space<E::VM>> Barrier for ObjectRememberingBarrier<E, S> {
    #[cold]
    fn flush(&mut self) {
        let mut modbuf = vec![];
        std::mem::swap(&mut modbuf, &mut self.modbuf);
        debug_assert!(
            !self.mmtk.scheduler.work_buckets[WorkBucketStage::Final].is_activated(),
            "{:?}",
            self as *const _
        );
        if !modbuf.is_empty() {
            self.mmtk.scheduler.work_buckets[WorkBucketStage::Closure]
                .add(ProcessModBuf::<E>::new(modbuf, self.meta));
        }
    }

    #[inline(always)]
    fn post_write_barrier(&mut self, target: WriteTarget) {
        match target {
            WriteTarget::Object(obj) => {
                self.enqueue_node(obj);
            }
            _ => unreachable!(),
        }
    }
}

/// Note: Please also disable vm-binding's barrier fast-path.
pub const ENABLE_BARRIER_COUNTER: bool = false;

pub static BARRIER_COUNTER: BarrierCounter = BarrierCounter {
    total: AtomicUsize::new(0),
    // slow: AtomicUsize::new(0),
    locked: AtomicUsize::new(0),
    locked_fast: AtomicUsize::new(0),
};

pub struct BarrierCounter {
    pub total: AtomicUsize,
    // pub slow: AtomicUsize,
    pub locked: AtomicUsize,
    pub locked_fast: AtomicUsize,
}

pub struct BarrierCounterResults {
    pub total: f64,
    pub locked: f64,
    // pub slow: f64,
    // pub take_rate: f64,
    pub locked_fast: f64,
}

impl BarrierCounter {
    pub fn reset(&self) {
        self.total.store(0, Ordering::SeqCst);
        self.locked.store(0, Ordering::SeqCst);
        self.locked_fast.store(0, Ordering::SeqCst);
    }

    pub fn get_results(&self) -> BarrierCounterResults {
        let total = self.total.load(Ordering::SeqCst) as f64;
        // let slow = self.slow.load(Ordering::SeqCst) as f64;
        let locked = self.locked.load(Ordering::SeqCst) as f64;
        let locked_fast = self.locked_fast.load(Ordering::SeqCst) as f64;
        BarrierCounterResults {
            total,
            locked,
            locked_fast,
        }
    }
}
