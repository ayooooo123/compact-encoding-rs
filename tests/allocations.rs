use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

use compact_encoding::{Bytes, Reader, Writer};

struct Allocator;
thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.get() {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNTING.get() {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

#[test]
fn message_buffers_decode_without_copying_or_allocating() {
    let mut writer = Writer::with_capacity(260);
    writer.buffer(&[42; 256]);
    let encoded = writer.finish();
    // Network buffers are already shared before multiple fields are sliced.
    let shared = encoded.clone();
    COUNTING.set(true);
    for _ in 0..10_000 {
        let mut reader = Reader::new(encoded.clone());
        let decoded = reader.buffer().unwrap();
        assert_eq!(decoded.as_ptr(), shared[3..].as_ptr());
        assert_eq!(decoded.len(), 256);
    }
    COUNTING.set(false);
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 0);
    eprintln!("PERF compact-buffer messages=10000 decode_allocations=0 payload_copies=0");

    let payload = Bytes::from_static(&[42; 256]);
    COUNTING.set(true);
    for _ in 0..10_000 {
        std::hint::black_box(compact_encoding::encode(&payload));
    }
    COUNTING.set(false);
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);
    assert_eq!(allocations, 10_000);
    eprintln!("PERF compact-buffer messages=10000 encode_allocations={allocations}");
}
