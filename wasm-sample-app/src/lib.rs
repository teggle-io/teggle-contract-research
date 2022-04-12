use std::os::raw::c_void;

/*
    Allocate a chunk of memory of `size` bytes in wasm module
*/
#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut c_void {
    use std::mem;
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    mem::forget(buf);
    return ptr as *mut c_void;
}

/*
    Deallocate a chunk of memory in wasm module
*/
#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut c_void, cap: usize) {
    unsafe {
        let _buf = Vec::from_raw_parts(ptr, 0, cap);
    }
}

#[no_mangle]
pub extern "C" fn run_wasm(input_data_ptr: *mut c_void, input_data_length: i32) -> i32 {
    //use std::ptr::copy;
    let input_data: Vec<u8> = unsafe {
        Vec::from_raw_parts(input_data_ptr as *mut u8,
                            input_data_length as usize, input_data_length as usize)
    };

    let input_data_str =  String::from_utf8(input_data).unwrap();

    //let inputs = serde_json::from_slice(&input_data).unwrap();
    //let object = #name {};
    //let result = object.run(inputs);

    //let return_data = serde_json::to_vec(&result).unwrap();


    //unsafe { copy(return_data.as_ptr(), input_data_ptr as *mut u8, return_data.len()); }

    //return_data.len() as i32

    return input_data_str.len() as i32

    //return 0 as i32
}
