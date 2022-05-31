extern crate wasm2_std;

use serde::{Deserialize, Serialize};
use wasm2_std::{Api, debug_print, Env, Extern, HandleResponse, Querier, StdError, StdResult, Storage};
use wasm2_storage::PrefixedStorage;

#[cfg(target_arch = "wasm32")]
mod wasm {
    //use super::contract;
    use wasm2_std::{debug_print, do_handle, ExternalApi, ExternalQuerier, ExternalStorage};

    #[no_mangle]
    extern "C" fn handle(env_ptr: u32, msg_ptr: u32) -> u32 {
        debug_print!("handle: env {}, msg {}", env_ptr, msg_ptr);

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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    DoNothing {}
}

pub const PREFIX_SIM: &[u8] = b"sim";

// For exact replica for test.
use std::any::type_name;

pub fn set_bin_data<T: Serialize, S: Storage>(
    storage: &mut S,
    key: &[u8],
    data: &T,
) -> StdResult<()> {
    let bin_data =
        bincode2::serialize(&data).map_err(|e| StdError::serialize_err(type_name::<T>(), e))?;
    storage.set(key, &bin_data);
    Ok(())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    _msg: HandleMsg,
) -> StdResult<HandleResponse> {
    debug_print!("handle called by {}", env.message.sender);

    let owner = deps.api.canonical_address(&env.message.sender)?;

    let mut sim_storage = PrefixedStorage::multilevel(
        &[PREFIX_SIM, &owner.as_slice()],
        &mut deps.storage,
    );

    let count: i32 = 1;
    for seq in 0..count {
        // For 1:1 comparison with the native version.
        //sim_storage.set(&[seq as u8], &[seq as u8]);

        set_bin_data(&mut sim_storage, &seq.to_le_bytes(), &seq)?;
    }

    return Ok(HandleResponse::default());
}
