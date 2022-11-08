#![no_std]
#![feature(alloc_error_handler)]

use scale::{Decode, Encode};

#[global_allocator]
static mut ALLOC: BumpAllocator = BumpAllocator {};

#[alloc_error_handler]
fn oom(_: core::alloc::Layout) -> ! {
    loop {}
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

use core::alloc::{
    GlobalAlloc,
    Layout,
};

static mut INNER: InnerAlloc = InnerAlloc::new();

/// A bump allocator suitable for use in a Wasm environment.
pub struct BumpAllocator;

unsafe impl GlobalAlloc for BumpAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match INNER.alloc(layout) {
            Some(start) => start as *mut u8,
            None => core::ptr::null_mut(),
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // A new page in Wasm is guaranteed to already be zero initialized, so we can just use our
        // regular `alloc` call here and save a bit of work.
        //
        // See: https://webassembly.github.io/spec/core/exec/modules.html#growing-memories
        self.alloc(layout)
    }

    #[inline]
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[cfg_attr(feature = "std", derive(Debug, Copy, Clone))]
struct InnerAlloc {
    /// Points to the start of the next available allocation.
    next: usize,

    /// The address of the upper limit of our heap.
    upper_limit: usize,
}

impl InnerAlloc {
    const fn new() -> Self {
        Self {
            next: 0x300000000,
            upper_limit: 0x400000000,
        }
    }

    /// Tries to allocate enough memory on the heap for the given `Layout`. If there is not enough
    /// room on the heap it'll try and grow it by a page.
    ///
    /// Note: This implementation results in internal fragmentation when allocating across pages.
    fn alloc(&mut self, layout: Layout) -> Option<usize> {
        let alloc_start = self.next;

        let aligned_size = layout.pad_to_align().size();
        let alloc_end = alloc_start.checked_add(aligned_size)?;

        if alloc_end > self.upper_limit {
            panic!("lol");
        } else {
            self.next = alloc_end;
            Some(alloc_start)
        }
    }
}


extern "C" {
    fn ext_syscall(r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> u64;
}

fn set_storage(key: &[u8], val: &[u8]) -> u32 {
    const SYSCALL_NO: u64 = 3;
    #[derive(Encode)]
    struct Input {
        key_ptr: u64,
        key_len: u32,
        value_ptr: u64,
        value_len: u32,
    }
    let input = Input {
        key_ptr: key.as_ptr() as usize as _,
        key_len: key.len() as _,
        value_ptr: val.as_ptr() as usize as _,
        value_len: val.len() as _,
    }
    .encode();
    unsafe { ext_syscall(SYSCALL_NO, input.as_ptr() as usize as _, 0, 0, 0) as _ }
}

fn get_storage(key: &[u8], output: &mut [u8]) -> Option<u32> {
    const SYSCALL_NO: u64 = 7;
    #[derive(Encode)]
    struct Input {
        key_ptr: u64,
        key_len: u32,
        out_ptr: u64,
        out_len_ptr: u64,
    }
    let mut len = output.len() as u64;
    let input = Input {
        key_ptr: key.as_ptr() as usize as _,
        key_len: key.len() as _,
        out_ptr: output.as_mut_ptr() as usize as _,
        out_len_ptr: (&mut len) as *mut _ as usize as _,
    }
    .encode();
    unsafe {
        if ext_syscall(SYSCALL_NO, input.as_ptr() as usize as _, 0, 0, 0) != 0 {
            return None;
        }
    }
    Some(len as _)
}

fn input(output: &mut [u8]) -> u32 {
    const SYSCALL_NO: u64 = 19;
    #[derive(Encode)]
    struct Input {
        out_ptr: u64,
        out_len_ptr: u64,
    }
    let mut len = output.len() as u64;
    let input = Input {
        out_ptr: output.as_mut_ptr() as usize as _,
        out_len_ptr: (&mut len) as *mut _ as usize as _,
    }
    .encode();
    unsafe {
        ext_syscall(SYSCALL_NO, input.as_ptr() as usize as _, 0, 0, 0);
    }
    len as _
}

#[no_mangle]
pub extern "C" fn entrypoint() {
    let mut buffer = [0u8; 1024];
    let len = input(buffer.as_mut());

    if len == 0 {
        return;
    }

    let add = u64::decode(&mut &buffer[..len as usize]).unwrap();
    let old_val = get_storage(&[0], buffer.as_mut())
        .map(|len| u64::decode(&mut &buffer[..len as usize]).unwrap())
        .unwrap_or(0);
    set_storage(&[0], (old_val + add).encode().as_ref());
}
