//extern crate wee_alloc;
extern crate wasm2_std;

use wasm2_std::{Api, debug_print, Env, Extern, HandleResponse, Querier, StdResult, Storage};
use wasm2_std::memory::{consume_region, Region};

// Use `wee_alloc` as the global allocator.
//#[global_allocator]
//static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[no_mangle]
pub extern "C" fn run_wasm(input_data_ptr: i32) -> i32 {
    let input_data: Vec<u8> = unsafe { consume_region(input_data_ptr as *mut Region) };
    let input_data_str =  String::from_utf8(input_data).unwrap();

    //let inputs = serde_json::from_slice(&input_data).unwrap();
    //let object = #name {};
    //let result = object.run(inputs);

    //let return_data = serde_json::to_vec(&result).unwrap();


    //unsafe { copy(return_data.as_ptr(), input_data_ptr as *mut u8, return_data.len()); }

    //return_data.len() as i32

    debug_print("Hello World");

    return input_data_str.len() as i32;

    //return 0 as i32
}

pub enum HandleMsg {

}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    _deps: &mut Extern<S, A, Q>,
    env: Env,
    _msg: HandleMsg,
) -> StdResult<HandleResponse> {
    debug_print!("handle called by {}", env.message.sender);

    return Ok(HandleResponse::default())
}
