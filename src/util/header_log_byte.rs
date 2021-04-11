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

pub const GC_BYTE_MASK : usize = 0b1111_1111 << 56;  // hard coded 56 = 7 * 8, for openjdk object model

fn get_log_byte(object: ObjectReference) -> &'static AtomicU8 {
    unsafe { &*(object.to_address()).to_ptr::<AtomicU8>() }
}

pub fn read_header(object: ObjectReference) -> usize {
    let slot = unsafe { &*(object.to_address()).to_ptr::<AtomicUsize>() };
    slot.load(Ordering::SeqCst)
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

pub fn get_replaced_log_byte(header: usize) -> &'static AtomicU8 {
    let real_log_byte_addr = header & !(LOCK_MASK as usize);
    unsafe { &*(Address::from_usize(real_log_byte_addr)).to_ptr::<AtomicU8>() }
}

pub fn compare_exchange_replaced_log_byte(header: usize, old_val: u8, new_val: u8) -> bool {
    get_replaced_log_byte(header)
        .compare_exchange(old_val, new_val, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

pub fn read_replaced_log_byte(header: usize) -> u8 {
    get_replaced_log_byte(header).load(Ordering::SeqCst)
}

pub fn write_replaced_log_byte(header: usize, val: u8) {
    get_replaced_log_byte(header).store(val, Ordering::SeqCst)
}

pub fn is_marked(object: ObjectReference) -> bool {
    let header = read_header(object);
    let log_byte = (header & 0b1111_1111) as u8;
    let lock_pattern = log_byte & LOCK_MASK;
    if lock_pattern == NO_LOCK {
        return log_byte & LOG_BIT_MASK != 0;
    } else if lock_pattern == LIGHT_LOCK || lock_pattern == HEAVY_LOCK {
        let real_log_byte = read_replaced_log_byte(header);
        return real_log_byte & LOG_BIT_MASK != 0;
    } else {
        panic!("Invalid lock pattern")
    }
}

pub fn set_mark_bit(object: ObjectReference) {
    let header = read_header(object);
    let log_byte = (header & 0b1111_1111) as u8;
    let lock_pattern = log_byte & LOCK_MASK;
    if lock_pattern == NO_LOCK {
        write_log_byte(object, log_byte | LOG_BIT_MASK);
    } else if lock_pattern == LIGHT_LOCK || lock_pattern == HEAVY_LOCK {
        write_replaced_log_byte(header, LOG_BIT_MASK | NO_LOCK);
    } else {
        panic!("Invalid lock pattern")
    }
}

pub fn unset_mark_bit(object: ObjectReference) {
    let header = read_header(object);
    let log_byte = (header & 0b1111_1111) as u8;
    let lock_pattern = log_byte & LOCK_MASK;
    if lock_pattern == NO_LOCK {
        write_log_byte(object, log_byte & !LOG_BIT_MASK);
    } else if lock_pattern == LIGHT_LOCK || lock_pattern == HEAVY_LOCK {
        write_replaced_log_byte(header, NO_LOCK);
    } else {
        panic!("Invalid lock pattern")
    }
}

pub fn spin_and_unlog_object(object: ObjectReference) {
    let header = read_header(object);
    if header & GC_BYTE_MASK != 0 {
        return;
    }
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
        let real_log_byte_addr = header & !(LOCK_MASK as usize);
        trace!("Try unlog locked object {} header at 0x{:x}", object, real_log_byte_addr);
        let real_log_byte_slot = unsafe { &*(Address::from_usize(real_log_byte_addr)).to_ptr::<AtomicU8>() };
        let real_log_byte = real_log_byte_slot.load(Ordering::SeqCst);
        if real_log_byte == UNLOGGED_NO_LOCK {
            trace!("Don unlog locked object {}", object);
            return;
        } else {
            real_log_byte_slot.compare_exchange(NO_LOCK, UNLOGGED_NO_LOCK, Ordering::SeqCst, Ordering::SeqCst).is_ok();
            trace!("TAG unlog locked object {}", object);
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
        let header = read_header(object);
        let real_log_byte_addr = header & !(LOCK_MASK as usize);
        let real_log_byte_slot = unsafe { &*(Address::from_usize(real_log_byte_addr)).to_ptr::<AtomicU8>() };
        real_log_byte_slot.store(UNLOGGED_NO_LOCK, Ordering::SeqCst);
    } else {
        panic!("Invalid lock pattern")
    }
}
