extern crate wasm2_std;

use wasm2_std::{Api, debug_print, Env, Extern, HandleResponse, Querier, StdResult, Storage};
use wasm2_std::memory::{consume_region, Region};

use serde::{Deserialize, Serialize};

#[cfg(target_arch = "wasm32")]
mod wasm {
    //use super::contract;
    use wasm2_std::{debug_print, do_handle, ExternalApi, ExternalQuerier, ExternalStorage};

    #[no_mangle]
    extern "C" fn handle(env_ptr: u32, msg_ptr: u32) -> u32 {
        debug_print!("testing: env {}, msg {}", env_ptr, msg_ptr);

        do_handle(
            &crate::handle::<ExternalStorage, ExternalApi, ExternalQuerier>,
            env_ptr,
            msg_ptr,
        )
    }

    /*
    #[no_mangle]
    extern "C" fn query(msg_ptr: u32) -> u32 {
        do_query(
            &contract::query::<ExternalStorage, ExternalApi, ExternalQuerier>,
            msg_ptr,
        )
    }
     */
}

#[no_mangle]
pub extern "C" fn run_wasm(input_data_ptr: i32) -> i32 {
    let input_data: Vec<u8> = unsafe { consume_region(input_data_ptr as *mut Region) };
    let input_data_str =  String::from_utf8(input_data).unwrap();

    let target: Option<String>  = Some("hello world".to_string());

    let encoded: Vec<u8> = bincode2::serialize(&target).unwrap();

    if encoded.len() > 0 {

    }

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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    DoNothing {}
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    _deps: &mut Extern<S, A, Q>,
    env: Env,
    _msg: HandleMsg,
) -> StdResult<HandleResponse> {

    debug_print!("handle called by {}", env.message.sender);

    return Ok(HandleResponse::default())
}
