use crate::util::ObjectReference;
use crate::vm::ObjectModel;
use crate::vm::VMBinding;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use crate::util::Address;

use super::constants;

pub const LOCK_MASK : u8 =  0b0000_0011;
pub const NO_LOCK : u8 =    0b0000_0001;
pub const LIGHT_LOCK : u8 = 0;
pub const HEAVY_LOCK : u8 = 0b0000_0010;

pub const LOG_BIT_MASK : u8 = 0b1000_0000;

pub const UNLOGGED_NO_LOCK : u8 = 0b1000_0001;

fn get_log_byte(object: ObjectReference) -> &'static AtomicU8 {
    unsafe { &*(object.to_address()).to_ptr::<AtomicU8>() }
}

fn get_header(object: ObjectReference) -> &'static AtomicUsize {
    unsafe { &*(object.to_address()).to_ptr::<AtomicUsize>() }
}

/// Atomically reads the current value of an object's first byte.
///
/// Returns an 8-bit unsigned integer
pub fn read_log_byte(object: ObjectReference) -> u8 {
    get_log_byte(object).load(Ordering::SeqCst)
}

/// Atomically writes a new value to the first byte of an object
pub fn write_log_byte(object: ObjectReference, val: u8) {
    get_log_byte(object).store(val, Ordering::SeqCst);
}

/// Atomically performs the compare-and-exchange operation on the first byte of an object.
///
/// Returns `true` if the operation succeeds.
pub fn compare_exchange_log_byte(
    object: ObjectReference,
    old_val: u8,
    new_val: u8,
) -> bool {
    get_log_byte(object)
        .compare_exchange(old_val, new_val, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

pub fn spin_and_unlog_object(object: ObjectReference) {
    let header = get_header(object).load(Ordering::SeqCst);
    let log_byte = (header & 0b1111_1111) as u8;
    if log_byte == UNLOGGED_NO_LOCK {
        return;
    }
    let lock_pattern = log_byte & LOCK_MASK;
    if lock_pattern == NO_LOCK {
        if compare_exchange_log_byte(object, log_byte, UNLOGGED_NO_LOCK) {
            return;
        } else {
            spin_and_unlog_object(object);
        }
    } else if lock_pattern == LIGHT_LOCK || lock_pattern == HEAVY_LOCK {
        info!("unlog locked object {}", object);
        let real_log_byte_addr = header & !(LOCK_MASK as usize);
        let real_log_byte_slot = unsafe { &*(Address::from_usize(real_log_byte_addr)).to_ptr::<AtomicU8>() };
        let real_log_byte = real_log_byte_slot.load(Ordering::SeqCst);
        if real_log_byte == UNLOGGED_NO_LOCK {
            return;
        } else {
            real_log_byte_slot.compare_exchange(NO_LOCK, UNLOGGED_NO_LOCK, Ordering::SeqCst, Ordering::SeqCst).is_ok();
            spin_and_unlog_object(object);
        }        
    } else {
        panic!("Invalid lock pattern")
    }
}

pub fn unlog_object(object: ObjectReference) {
    let log_byte = read_log_byte(object);
    let lock_pattern = log_byte & LOCK_MASK;
    if lock_pattern == NO_LOCK {
        write_log_byte(object, UNLOGGED_NO_LOCK);
    } else if lock_pattern == LIGHT_LOCK || lock_pattern == HEAVY_LOCK {
        let header = get_header(object).load(Ordering::SeqCst);
        let real_log_byte_addr = header & !(LOCK_MASK as usize);
        let real_log_byte_slot = unsafe { &*(Address::from_usize(real_log_byte_addr)).to_ptr::<AtomicU8>() };
        real_log_byte_slot.store(UNLOGGED_NO_LOCK, Ordering::SeqCst);
    } else {
        panic!("Invalid lock pattern")
    }
}
