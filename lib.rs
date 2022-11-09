use scale::{Decode, Encode};

extern "C" {
    fn ext_syscall(r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> u64;
}

fn deposit_event(data: &[u8]) {
    const SYSCALL_NO: u64 = 38;
    #[derive(Encode)]
    struct Input {
        topics_ptr: u64,
        topics_len: u32,
        data_ptr: u64,
        data_len: u32,
    }
    let input = Input {
        topics_ptr: 0,
        topics_len: 0,
        data_ptr: data.as_ptr() as usize as _,
        data_len: data.len() as _,
    }
    .encode();
    unsafe {
        ext_syscall(SYSCALL_NO, input.as_ptr() as usize as _, 0, 0, 0);
    }
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
        let ret = ext_syscall(SYSCALL_NO, input.as_ptr() as usize as _, 0, 0, 0);
        deposit_event(ret.to_le_bytes().as_ref());
        if ret != 0 {
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

    let mut input = &buffer[..len as usize];
    deposit_event(input);

    let add = u64::decode(&mut input).unwrap();
    let old_val = get_storage(&[0], buffer.as_mut())
        .map(|len| u64::decode(&mut &buffer[..len as usize]).unwrap())
        .unwrap_or(0);

    deposit_event(old_val.to_le_bytes().as_ref());

    set_storage(&[0], (old_val + add).encode().as_ref());
}
