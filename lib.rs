#![no_std]
#![feature(alloc_error_handler)]

use scale::{Decode, Encode};
use core::alloc::{
    GlobalAlloc,
    Layout,
};
use core::cell::RefCell;
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};

#[alloc_error_handler]
fn oom(_: core::alloc::Layout) -> ! {
    unsafe { abort() }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { abort() }
}


struct Alloc {
    heap: RefCell<linked_list_allocator::Heap>,
}

impl Alloc {
    const fn new() -> Self {
        Self {
            heap: RefCell::new(linked_list_allocator::Heap::empty()),
        }
    }
}

unsafe impl GlobalAlloc for Alloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.heap
            .borrow_mut()
            .allocate_first_fit(layout)
            .ok()
            .map_or(ptr::null_mut(), |allocation| allocation.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.heap
            .borrow_mut()
            .deallocate(NonNull::new_unchecked(ptr), layout)
    }
}

#[global_allocator]
static mut ALLOCATOR: Alloc = Alloc::new();

pub unsafe fn init() {
    const HEAP_SIZE: usize = 0x8000;
    static mut HEAP: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    ALLOCATOR
        .heap
        .borrow_mut()
        .init(HEAP.as_mut_ptr() as *mut u8, HEAP_SIZE)
}


extern "C" {
    fn ext_syscall(r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> u64;
    fn abort() -> !;
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
    unsafe {
        init()
    }

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
