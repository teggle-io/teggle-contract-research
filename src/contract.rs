extern crate libflate;
extern crate wain_ast;
extern crate wain_exec;
extern crate wain_syntax_binary;
extern crate wain_validate;

use std::io::{Cursor, Read};
use std::str;

use cosmwasm_std::{Api, Binary, CanonicalAddr, CosmosMsg, debug_print, Env, Extern, HandleResponse, HumanAddr, InitResponse, plaintext_log, Querier, StdError, StdResult, Storage, to_binary};
use cosmwasm_storage::PrefixedStorage;
use libflate::gzip::Decoder;
use schemars::_serde_json::to_vec;
use secret_toolkit::utils::{HandleCallback, Query};
use wain_ast::{Root, ValType};
use wain_exec::{check_func_signature, Importer, ImportInvalidError, ImportInvokeError, Memory, Runtime, Stack, Value};
use wain_exec::trap::Trap;
use wain_syntax_binary::parse;
use wain_syntax_binary::source::BinarySource;
use wain_validate::validate;

use crate::msg::{BatchTxn, CountResponse, HandleMsg, InitMsg, OtherHandleMsg, QueryMsg, WasmHandleMsg};
use crate::state::{config, config_read, CONTRACT_DATA_KEY, set_bin_data, State};

pub const PREFIX_SIM: &[u8] = b"sim";

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    let state = State {
        count: msg.count,
        owner: deps.api.canonical_address(&env.message.sender)?,
    };

    config(&mut deps.storage).save(&state)?;

    debug_print!("Contract was initialized by {}", env.message.sender);

    Ok(InitResponse::default())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    debug_print!("handle called by {}", env.message.sender);

    match msg {
        HandleMsg::Increment {} => try_increment(deps, env),
        HandleMsg::Reset { count } => try_reset(deps, env, count),
        HandleMsg::Simulate { count } => try_simulate(deps, env, count),
        HandleMsg::SimulateOther { count } => try_simulate_other(deps, env, count),
        HandleMsg::SimulateQuery { count } => try_simulate_query(deps, env, count),
        HandleMsg::ProcessBatch { transactions } => try_process_batch(deps, env, transactions),
        HandleMsg::SaveContract { data } => try_save_contract(deps, env, data),
        HandleMsg::LoadContract {} => try_load_contract(deps, env),
        HandleMsg::RunWasm {} => try_run_wasm(deps, env),
    }
}

pub fn try_increment<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
) -> StdResult<HandleResponse> {
    config(&mut deps.storage).update(|mut state| {
        state.count += 1;
        debug_print!("count = {}", state.count);
        Ok(state)
    })?;

    debug_print("count incremented successfully");

    //Ok(HandleResponse::default())

    Ok(HandleResponse {
        messages: vec![],
        log: vec![plaintext_log("MY_LOG", "MY_LOG_VALUE")],
        data: Some(to_binary("THIS IS AN ORDINARY STRING LET US SEE")?),
    })
}

pub fn try_reset<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    count: i32,
) -> StdResult<HandleResponse> {
    let sender_address_raw = deps.api.canonical_address(&env.message.sender)?;
    config(&mut deps.storage).update(|mut state| {
        if sender_address_raw != state.owner {
            return Err(StdError::Unauthorized { backtrace: None });
        }
        state.count = count;
        Ok(state)
    })?;
    debug_print("count reset successfully");
    Ok(HandleResponse::default())
}

pub fn try_simulate<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    count: i32,
) -> StdResult<HandleResponse> {
    let owner = deps.api.canonical_address(&env.message.sender)?;

    for seq in 0..count {
        let mut sim_storage = PrefixedStorage::multilevel(
            &[PREFIX_SIM, &owner.as_slice()],
            &mut deps.storage,
        );

        set_bin_data(&mut sim_storage, &seq.to_be_bytes(), &seq)?;
    }

    debug_print("simulated successfully");
    Ok(HandleResponse::default())
}

pub fn try_simulate_other<S: Storage, A: Api, Q: Querier>(
    _deps: &mut Extern<S, A, Q>,
    _env: Env,
    count: i32,
) -> StdResult<HandleResponse> {
    let other_addr = "secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg";
    let other_code = "D20C11EDECB628C87F53454DF16D34F7509ABE41DCA8EAA5A0EFE12D5979120A";

    let mut messages: Vec<CosmosMsg> = Vec::new();

    for _seq in 0..count {
        let sim_msg = OtherHandleMsg::Simulate {
            count: 1,
        };

        messages.push(sim_msg.to_cosmos_msg(
            other_code.to_string(),
            HumanAddr(other_addr.to_string()),
            None,
        )?)
    }

    debug_print("simulated successfully");

    Ok(HandleResponse {
        messages,
        log: vec![],
        data: None,
    })
}

pub fn try_simulate_query<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    count: i32,
) -> StdResult<HandleResponse> {
    let other_addr = "secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg";
    let other_code = "D20C11EDECB628C87F53454DF16D34F7509ABE41DCA8EAA5A0EFE12D5979120A";

    for _seq in 0..count {
        let get_count = QueryMsg::GetCount {};

        let _count_response: CountResponse = get_count.query(
            &deps.querier,
            other_code.to_string(),
            HumanAddr(other_addr.to_string()),
        )?;
    }

    debug_print("simulated successfully");

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: None,
    })
}

pub fn try_process_batch<S: Storage, A: Api, Q: Querier>(
    _deps: &mut Extern<S, A, Q>,
    _env: Env,
    transactions: Vec<BatchTxn>,
) -> StdResult<HandleResponse> {
    for tx in transactions {
        let str_payload = str::from_utf8(tx.payload.as_slice());
        if str_payload.is_ok() {
            debug_print("================");
            debug_print("txn");
            debug_print("----------------");
            debug_print!("id: {}", tx.id);
            debug_print!("auth: {}", tx.auth);
            debug_print!("payload: {}", str_payload.unwrap());
            debug_print("================");
        }
    }

    debug_print("processed batch successfully");

    Ok(HandleResponse::default())
}

// TODO, what should this be?
const MIN_CONTRACT_LEN: usize = 1000;

pub fn try_save_contract<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    data: Binary,
) -> StdResult<HandleResponse> {
    let data_u8 = data.as_slice();
    if data_u8.len() <= MIN_CONTRACT_LEN {
        return Err(StdError::GenericErr {
            msg: format!("data for contract invalid length (not big enough)"),
            backtrace: None,
        });
    }

    // TODO: Authentication

    // Verify
    let wasm = deflate_wasm(&data_u8)?;
    let tree = parse_wasm(wasm.as_slice())?;

    // Validate module
    if let Err(err) = validate(&tree) {
        return Err(StdError::GenericErr {
            msg: format!("WASM is invalid: {err}"),
            backtrace: None,
        });
    }

    debug_print("WASM: verification successful");

    // Store
    // raw storage with no serialization.
    deps.storage.set(CONTRACT_DATA_KEY, data_u8);

    debug_print!("saved WASM bytes: {}", data.len());

    Ok(HandleResponse::default())
}

pub fn try_load_contract<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
) -> StdResult<HandleResponse> {
    let wasm_bin = deps.storage.get(CONTRACT_DATA_KEY).unwrap();

    debug_print!("loaded WASM bytes: {}", wasm_bin.len());

    Ok(HandleResponse::default())
}


struct CortexImporter<'d, S: Storage, A: Api, Q: Querier> {
    deps: &'d mut Extern<S, A, Q>,
}

fn pop_value(stack: &mut Stack, memory: &mut Memory) -> Result<Vec<u8>, ImportInvokeError> {
    memory
        .get_region(stack.pop())
        .map_err(map_trap_err_to_import_err)
}

fn map_trap_err_to_import_err(err: Box<Trap>) -> ImportInvokeError {
    return ImportInvokeError::Fatal {
        message: err.to_string(),
    };
}

fn map_trap_err_to_std_err(err: Box<Trap>) -> StdError {
    return StdError::GenericErr {
        msg: err.to_string(),
        backtrace: None
    };
}

impl<'d, S: Storage, A: Api, Q: Querier> Importer for CortexImporter<'d, S, A, Q> {
    fn validate(&self, name: &str, params: &[ValType], ret: Option<ValType>) -> Option<ImportInvalidError> {
        match name {
            "db_read" => check_func_signature(params, ret,
                                              &[ValType::I32],
                                              Some(ValType::I32)),
            "write_db" => check_func_signature(params, ret,
                                               &[ValType::I32, ValType::I32],
                                               None),
            "db_remove" => check_func_signature(params, ret,
                                                &[ValType::I32],
                                                None),
            "canonicalize_address" => check_func_signature(params, ret,
                                                           &[ValType::I32, ValType::I32],
                                                           Some(ValType::I32)),
            "humanize_address" => check_func_signature(params, ret,
                                                       &[ValType::I32, ValType::I32],
                                                       Some(ValType::I32)),
            "query_chain" => check_func_signature(params, ret,
                                                  &[ValType::I32],
                                                  Some(ValType::I32)),
            "gas" => check_func_signature(params, ret,
                                          &[ValType::I32],
                                          None),


            "tuplet_log" => check_func_signature(params, ret,
                                                  &[ValType::I32, ValType::I32, ValType::I32],
                                                 None),
            #[cfg(feature = "debug-print")]
            "debug_print" => check_func_signature(params, ret,
                                                  &[ValType::I32], None),
            _ => Some(ImportInvalidError::NotFound),
        }
    }

    // TODO: Abstract all of this more (obviously mot inline in a file like this either!).
    fn call(&mut self, name: &str, stack: &mut Stack, memory: &mut Memory) -> Result<(), ImportInvokeError> {
        match name {
            // fn read_db(key: *const c_void) -> i32;
            "db_read" => {
                let key_bytes = pop_value(stack, memory)?;

                match self.deps.storage.get(key_bytes.as_slice()) {
                    Some(v) => stack.push_pending_alloc(v),
                    None => stack.push::<i32>(0)
                }

                Ok(())
            }
            // fn write_db(key: *const c_void, value: *mut c_void);
            "write_db" => {
                let value_bytes = pop_value(stack, memory)?;
                let key_bytes = pop_value(stack, memory)?;

                self.deps.storage.set(key_bytes.as_slice(), value_bytes.as_slice());

                Ok(())
            }
            // fn db_remove(key: *const c_void) -> i32;
            "db_remove" => {
                let key_bytes = pop_value(stack, memory)?;

                self.deps.storage.remove(key_bytes.as_slice());

                Ok(())
            }
            // fn canonicalize_address(human: *const c_void, canonical: *mut c_void) -> i32;
            "canonicalize_address" => {
                let dest_ptr = stack.pop();
                let addr_bytes = pop_value(stack, memory)?;

                match self.deps.api.canonical_address(
                    &HumanAddr::from(String::from_utf8(addr_bytes).unwrap())) {
                    Ok(v) => {
                        memory.set_region(dest_ptr, v.as_slice())
                            .map_err(map_trap_err_to_import_err)?;
                        stack.push::<i32>(0);
                    }
                    Err(err) => {
                        stack.push_pending_alloc(format!("{err}").into_bytes());
                    }
                }

                Ok(())
            }
            // fn humanize_address(canonical: *const c_void, human: *mut c_void) -> i32;
            "humanize_address" => {
                let dest_ptr = stack.pop();
                let addr_bytes = pop_value(stack, memory)?;

                match self.deps.api.human_address(
                    &CanonicalAddr::from(addr_bytes)) {
                    Ok(v) => {
                        memory.set_region(dest_ptr,
                                          v.to_string().as_bytes())
                            .map_err(map_trap_err_to_import_err)?;
                        stack.push::<i32>(0);
                    }
                    Err(err) => {
                        stack.push_pending_alloc(format!("{err}").into_bytes());
                    }
                }

                Ok(())
            }
            // fn query_chain(request_ptr: *const c_void);
            "query_chain" => {
                let _request_bytes = pop_value(stack, memory)?;

                // TODO: can't make QueryRequest without known type. may need low level access.
                //let request: QueryRequest = from_slice(request_bytes.as_slice()).unwrap();
                //self.deps.querier.query(&request);

                Ok(())
            }
            // fn gas(request_ptr: *const c_void);
            "gas" => {
                // TODO

                Ok(())
            }

            "tuplet_log" => {
                //println!("tuplet_log: stack size", stack.);

                let c = stack.pop::<i32>();
                let b = stack.pop::<i32>();
                let a = stack.pop::<i32>();

                println!("tuplet_log: {} {} {}", a, b, c);

                Ok(())
            }

            #[cfg(feature = "debug-print")]
            "debug_print" => {
                let msg_str_bytes = pop_value(stack, memory)?;

                // cortex.v1 (example of module name and version).
                //debug_print!("WASM2[cortex.v1]: {}", String::from_utf8(msg_str_bytes).unwrap());

                // TODO: REMOVE
                println!("WASM2[cortex.v1]: {}", String::from_utf8(msg_str_bytes).unwrap());

                Ok(())
            }
            _ => unreachable!("fatal(call): invalid import function '{}'", name)
        }
    }
}

fn deflate_wasm(compressed_bytes: &[u8]) -> Result<Vec<u8>, StdError> {
    let mut decoder = Decoder::new(
        Cursor::new(compressed_bytes)).unwrap();
    let mut buf = Vec::new();

    let res = decoder.read_to_end(&mut buf);
    if !res.is_ok() {
        return Err(StdError::GenericErr {
            msg: format!("failed to deflate WASM binary"),
            backtrace: None,
        });
    }

    debug_print!("WASM: deflated contract ({} bytes)", res.unwrap());

    return Ok(buf);
}

fn parse_wasm(wasm_binary_u8: &[u8]) -> Result<Root<'_, BinarySource<'_>>, StdError> {
    return match parse(wasm_binary_u8) {
        Ok(tree) => {
            debug_print("WASM: parsed module");

            Ok(tree)
        }
        Err(err) => {
            Err(StdError::GenericErr {
                msg: format!("failed to parse WASM binary: {err}"),
                backtrace: None,
            })
        }
    };
}

pub fn try_run_wasm<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    debug_print("WASM: start");

    let data_u8 = deps.storage.get(CONTRACT_DATA_KEY);
    if data_u8.is_none() {
        return Err(StdError::GenericErr {
            msg: format!("no WASM contract found to run."),
            backtrace: None,
        });
    }

    debug_print("WASM: loaded contract");

    let wasm = deflate_wasm(&data_u8.unwrap())?;
    let tree = parse_wasm(&wasm.as_slice())?;

    debug_print("WASM: loaded WASM module");

    // Make abstract machine runtime. It instantiates a module
    let importer = CortexImporter { deps };

    let mut runtime: Runtime<CortexImporter<S, A, Q>> = match Runtime::instantiate(&tree.module, importer) {
        Ok(m) => m,
        Err(err) => {
            return Err(StdError::GenericErr {
                msg: format!("failed to instantiate WASM runtime: {err}"),
                backtrace: None,
            });
        }
    };

    debug_print("WASM[04]: loaded WASM instance");

    /*
    // Allocate a string for the input data inside wasm module
    let input_data = b"Hello World..";
    let input_data_wasm_ptr = match runtime.allocate_and_set_region(input_data) {
        Ok(m) => m,
        _ => {
            return Err(StdError::GenericErr {
                msg: format!("failed to set region in WASM VM"),
                backtrace: None,
            });
        }
    };

    debug_print("WASM[05]: wrote to WASM memory");

    match runtime.invoke("run_wasm", &[Value::I32(input_data_wasm_ptr as i32)]) {
        Ok(ret) => {
            match ret.unwrap() {
                Value::I32(bytes_len) => {
                    // TODO

                    debug_print!("WASM[06]: WASM result len: {bytes_len}");
                }
                _ => {
                    return Err(StdError::GenericErr {
                        msg: format!("expected i32 to be returned by 'run_wasm' call"),
                        backtrace: None,
                    });
                }
            }
        }
        Err(err) => {
            return Err(StdError::GenericErr {
                msg: format!("failed to call 'run_wasm' in WASM: {err}"),
                backtrace: None,
            });
        }
    }
    */

    // TODO: REMOVE

    println!("allocating env ...");

    let env_bytes = to_vec(&env).unwrap();

    println!("env bytes: {}", env_bytes.len());

    let env_bytes_ptr = runtime.allocate_and_set_region(env_bytes.as_slice())
        .map_err(map_trap_err_to_std_err)?;

    println!("allocating msg ...");

    let msg = WasmHandleMsg::DoNothing {};
    let msg_bytes = to_vec(&msg).unwrap();
    let msg_bytes_ptr = runtime.allocate_and_set_region(msg_bytes.as_slice())
        .map_err(map_trap_err_to_std_err)?;

    // TODO: REMOVE
    println!("running handle ...");

    match runtime.invoke("handle", &[Value::I32(env_bytes_ptr as i32),
        Value::I32(msg_bytes_ptr as i32)]) {
        Ok(ret) => {
            match ret.unwrap() {
                Value::I32(bytes_len) => {
                    // TODO

                    debug_print!("WASM[06]: WASM result len: {bytes_len}");
                }
                _ => {
                    return Err(StdError::GenericErr {
                        msg: format!("expected i32 to be returned by 'run_wasm' call"),
                        backtrace: None,
                    });
                }
            }
        }
        Err(err) => {
            return Err(StdError::GenericErr {
                msg: format!("failed to call 'handle' in WASM: {err}"),
                backtrace: None,
            });
        }
    }

    debug_print("WASM[99]: end");

    Ok(HandleResponse::default())
}

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetCount {} => to_binary(&query_count(deps)?),
        QueryMsg::GetIndexMeta { auth } => to_binary(&query_index_meta(deps, auth)?),
    }
}

fn query_count<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> StdResult<CountResponse> {
    let state = config_read(&deps.storage).load()?;
    Ok(CountResponse { count: state.count })
}

fn query_index_meta<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, auth: String) -> StdResult<CountResponse> {
    if auth != "123" {
        return Err(StdError::Unauthorized { backtrace: None });
    }

    // Same as above, just for testing.
    let state = config_read(&deps.storage).load()?;
    Ok(CountResponse { count: state.count })
}

#[cfg(test)]
mod tests {
    use std::borrow::Borrow;
    use std::fs;
    use std::time::SystemTime;

    use cosmwasm_std::{coins, from_binary, StdError};
    use cosmwasm_std::testing::{mock_dependencies, mock_env};

    use crate::msg::HandleMsg::{RunWasm, SaveContract};

    use super::*;

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies(20, &[]);

        let msg = InitMsg { count: 17 };
        let env = mock_env("creator", &coins(1000, "earth"));

        // we can just call .unwrap() to assert this was a success
        let res = init(&mut deps, env, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query(&deps, QueryMsg::GetCount {}).unwrap();
        let value: CountResponse = from_binary(&res).unwrap();
        assert_eq!(17, value.count);
    }

    #[test]
    fn increment() {
        let mut deps = mock_dependencies(20, &coins(2, "token"));

        let msg = InitMsg { count: 17 };
        let env = mock_env("creator", &coins(2, "token"));
        let _res = init(&mut deps, env, msg).unwrap();

        // anyone can increment
        let env = mock_env("anyone", &coins(2, "token"));
        let msg = HandleMsg::Increment {};
        let _res = handle(&mut deps, env, msg).unwrap();

        // should increase counter by 1
        let res = query(&deps, QueryMsg::GetCount {}).unwrap();
        let value: CountResponse = from_binary(&res).unwrap();
        assert_eq!(18, value.count);
    }

    #[test]
    fn reset() {
        let mut deps = mock_dependencies(20, &coins(2, "token"));

        let msg = InitMsg { count: 17 };
        let env = mock_env("creator", &coins(2, "token"));
        let _res = init(&mut deps, env, msg).unwrap();

        // not anyone can reset
        let unauth_env = mock_env("anyone", &coins(2, "token"));
        let msg = HandleMsg::Reset { count: 5 };
        let res = handle(&mut deps, unauth_env, msg);
        match res {
            Err(StdError::Unauthorized { .. }) => {}
            _ => panic!("Must return unauthorized error"),
        }

        // only the original creator can reset the counter
        let auth_env = mock_env("creator", &coins(2, "token"));
        let msg = HandleMsg::Reset { count: 5 };
        let _res = handle(&mut deps, auth_env, msg).unwrap();

        // should now be 5
        let res = query(&deps, QueryMsg::GetCount {}).unwrap();
        let value: CountResponse = from_binary(&res).unwrap();
        assert_eq!(5, value.count);
    }

    #[test]
    fn run_wasm() {
        let mut deps = mock_dependencies(20, &coins(2, "token"));

        //// Save Contract
        // normal optimize.
        //let contract_bin = Binary::from_base64("H4sIAAAAAAACA919C3hdVZnoeu3HOfucZKekbZr0sc+hQPo+eTQvXt3VpA3pA0RA5NGGNkDPKQlJTwNelZw+VJRXcTojIjIFO4KKwsxlfIFSR3RwRMH7oTDKHYuDI983XKwOzjBXJPf//7X2PjtpCjrP77vpl+y19lp7rX/961//e++ywV3XcMYY31K7VUxM8ImtcoIuUGFbOZY4FPAmVW/Yak1MUIWxrcqUoBMV4apboeBMTERFcQP8lTtLSgrGlFKWJZWAH5Vmtm0JRpUUQiH1D9atqCaEy/DHsgSHzgL62UJmHRiKO9AqMwA9Y55tM3imhvpyZfFr+SmnWJKzOnuenOBhpXKEeRMs/PJhfT2CV2etbV8zdM3I2HsEswZ37hzZxrizfUiXhDu2e3jLdYAgJtNbtmwfLA9uGRreLrm3ZcvVQ4PXbrlicNeQFKmlnIXcW8y659j11knOvMam+QsXBdbpPWe8/czNm9ZttfrPe9fFV7/7kkuvvCr9Zw/wUj0LWKiKzbDwNQGDi+97XivnE2KNgBsh24T3szzkOZ4Rnt/FPLjLfZXnWUalTrjDPY8FHHvi45fB4yezMCjlxWIWiNAtBtDqDwaiWbghXwf9or7QGhShE6+FYiCWiEynqIcS7xC+vmTgwjqES+P45zLPZTTaLE8y7i1kBCUtoBcBgmtelxCSgBaCdwFeuguDmK4cOzzCuTCwysU4Fod/opjnA9kYMXkR8nJeUZPqb8rz0A3gd6Apx+EBASuRYUMxBFhZIAPRAQuQBAisIcM9aMUSXOF5GfpFPxVIaA15Hz1KACHMHG8rABwxisWcIBACGpnhyDAB4auWNuJ2BB73if7p0kTI8zBRyNZnWSMinOUVDg0llYU1ZGExGenlACjYUBswlAVIEEyOu+rlBfSGjQ6grz83L7LQwhACRRRANYE1lpNYlgQbbjFC6T25SNTCuQSM+qW8ixil/fkN36zWANW/L3RD18+F9fi3GPp0KYXXjYYSiCVk+k4oyqW8Bftu9TcFbGNWowFbcio8dugIox2ENQaqhHtAy4ZKWBH9sOpwERQnJyedAUSBCm34dcevyrPSeMhHkWbLpfCsopd3YKLw9XuPML0DsBsqcPzF5ZwNqxOSQPdPAUgUDBvABaHim5EyYGssPAGERUREWE+DWLDLFqDFDheMh2oUlqjHXteEDU05CS0cJoAjhZuMBJBjiG6RFR7OGvLAKfv5aJmjSBhATf7JV08FFu56cg1uBsEoArUZigAhbH7/aB6mEkRwUODQozVPE8Lm4taGr3/qiD4pGwFv0A4Pbm5CKgmUvzIHg/qeWKM3I+AbAUpsWEbnbjkQSkVsxvMLtQzCzkM5npehLIevAtRF2JKJ8GUNf96CBclyXo7ioYfjDxREbYiOMaQdDrSIIOARl3jJaHrLaOLCB5ARBKroL4WSX8CDjBQa+posNMlYpYANNGkaSR6IKiCwbACTj+dZKEd7cbMjNGzMOsTiDM4Ruc7xKBf+KURvAEMrEosk6jAox6M9kJeEbABXIvojrHsGrRaiNULqQNYySLUQqdUd6YVTyhBSu4pQFu4/TM1wbKP1OIBYu5y3R3vxfCBmpUdnbWIXUjkv4joB8eHrh8wCuGE1AJ4eNy/X0dZKxDZxrur2WOENAbtuFM807g4M5S8FQAtA7g7SBqw4XDSa50CruF/lUUDXcTMKMyOfOiOPZuSJGaOFJebV+CHkwfbh4IhtlcQWkuE06qsiK0mHdoIO2VQ6tIkOGdIhUZ6rIctoqsxocF2Phg0s6EvTBwqfEoQR24xlB040lm3IF+6ZxTJ9sWcaC3nnDIQOzDdm7+Zf4vDyAeSphw0mAjUAhOBqBguDTOWxwHuVn/M7ApeeROYJcKe8GFcsIkxEMY2MLSi5WDRhjlOJ7tHhXwokXqBhkIMAhYvqavQKSWQJ4hpMcxB6wPUQDjdnhTdjLxfFs6QyTAOEi88fwOkPmNUBheO56m+CFjrVN+oGAPMglHKMDuPqgPeZw0AHD5nE/RF+ehHkgbGsBPqFvm2kIrQH1rpIaxDRoHl7o5oIaBwQvvaAFTIPuC0NVR2P2CYniJBCirB4DQrCJ9fo59k6Q24AD/KsKTP3wfZGcyaejp8lHguLEgPItONVwc7R2YCmfK3e5XxNKZxbygNygc5xF23ghoDHINpVUQS9xQbcO0CPNcjiNZ3kUnqAnOFLuQwBhPwMxkrTs+lSPgsHMI2bgtRGKkuQCVKBVywG2WIpn0IcpINUyMdQM3DNiPVmRD1yFnv4K4MsPOqFbqlYxL6HEaeVSoVUHARtGeFhCWDEDxyYKLxLVzuh3Ql8uISH4rNzB4GDpYOHI7rD/oEDJUmKIawV2RfcUEFtwPMoMgZIFAZ2H7B5uAQCUEcIXemvgL5aumE9g5RK/IUn+EuCq0jkg+U8P46rAEVEnIBrjclFxTJWZzNauXWJGHH/Lc17kMyR7oCgEGLcBUboA30DypLKNg4VsFIxrwULjyUJMJtSkRajiqUcChJDX+vMgW7GGfpQxMAkIAdBG89aRs+RkVz3PdLzwoxRaYzSnLeRmm1EfQbnmpl5AyceN/xbAhQIRCCR4jKWZ4groqSIeUE3OvMkaIiGDF91PE1xjJgSPoYDxOeUmE4+4jHmySSfsfWh1eyV1NUqbqNRYiBk0c9CJ824eMT3IuaXhBG4mYZPomxEjX0FKZ+bSbYpP1NtVtOF0wlUIzaTavRWIslMA1zuAUTL5KKOtzwdlXugI4JCyMTK66aC17jlALbsv0dX9ie73YGVm03Lzcluh7By0FQOJrvdj5W7TOWuZLeHsHLYVA4nu30ZKw+YygPJbkew8rCpPJzs9miy5QmsPGoqjycrT2PlcVN5Mll5DitPmsozycpRrDxjKs8nKy9h5XlTeTFZOYaVF03l5WTlNay8bCqvJiuVe4/oO7Q/WHndVF6/J9FyAFv232v2J9ntDqzcbFpuTnY7hJWDpnIw2e1+rNxlKncluz2ElcOmcjjZ7ctYecBUHkh2O4KVh03l4WS3J7DyqKk8muz2NFYeN5XHk92ew8qTpvJksttRrDxjKs8ku72EledN5flkt2NYedFUXkx2ew0rL5vKy8luryZbtGwTRrZZRrbZSalJ/Bq4c54Dc2JTpaaNRi1ITV7U/AxP9xSpGY0szcgkFkBqol0pZpSaqA/wpBq4Mcv+XVwTdDOwWtEn431RcGsCeVODNqo0A830kdZdTwZYfTHPSRI2aY3faJaRwkKaTCZveJexMIjP+0W0kqRECxhMIZCwMJSkMdA449ABDcNm4efIPAZ5YpHqiVaO6s2yCJz5sZWWF0bjUoC9+kDBsyDsmowDhWu/hohqjOy9yOhDswPGIslVS2y9QzTgLT8viK2L2CPVUDX3tSMJKkGkFGOzd1hw0CDZWtBaAAJyTvCqc4JXnRM8tNGVNH5VXmrnhIydEzD/fFhItDaUBDkRWQFVUxVkiCrnLZQhkgxE2MjFORS5pwQg27nxL9ADAJ8WLGTrMS2+WDmncBNgrthlkbfM4kCPQHcF0EfeDIjmLO2s0WaMbjNFqQFKhVoDoNGiiTxtYzagh093xke93VxO4BYmz4wg3bSiT5NIkG+M4Dc9LsocF3Xi4/IIh2lj76T2+IV8msdPvpnHD702Ivb40dLqjcpuPH7CePzQnBPa4ydij59IevxE1eOHRdzlhMePnGsi4fH7niLCwjVGxABPn2ZMmJykanOvtrGLpHpKf1U+NonXmSlR85Prsgl7LSCE+yuI9iUSgfZLnUApVLFSaOGBs/C4ZADt1lsqhcI/VfuOcDaYoWrMBYLcEQlYtS7GjtPFcLsiI3R5rVclkKlqZaJbxOaSg8fGbNXURS80asLwqN7qyBjQqxfx6qNN1CBHqxdvuXrtQTsODO08RdwnfWu1xrUmZnatofEhynlxnGtNGOODezkRudbENNcagur92ib+7regqYheRDQm3pSsBFm6M5EVP46shHFbw1JWkHv/P5Gs8BwbwqL5MpHnJCYuHXb4PYhL/H7EJU5MXH1a0nCiJFHEkxovmOsF83jBkVdOwxctmP8elCSmUlIC62jGzEDdHnFCQsbmLH8rdzyb4o433g50uxuMYlFzYWa4MDdcGNifqHqmFLFBRtw4L1A7iXwePOnz4FN8Hnwmn4fxnWjUNWbwtl9Xwq00c0Xr2wi3iOlPmDNNwpcMcT+jjaUHzBO8pM06mMWva6z1qPeJ3dniRO7sxJl7U3e2N8IzE+SkiFSdpPEGwGqc2OgFQs3KxSOsJQPqWTkVkQ4oDzmwxUF0ofqEOHqALD8Yif4MNNGA3j8KkHex95CHKYzExE5oran56Zwkj7reRu+tSENNIQ2BDHCgKeAlDNbgeTiBZz6vYnekKvlpDDXhjrTkSAzjVsBxIdc806EmYhkwYGkUOgkDniS3u6DABXpBAjnQVET6BEhK1BoJQH8J7bj+W0t8hlyd2nxW5METRe3i9puRhyEPNMhRxY1Zkv8UEMErjaM90EtIYaYhJXJpv4AjNHpZtvbVf737H1751Gf/9Q3mZdjaH3x38qEvHL73R2nvoIk0+hRpjDRI0qujWCvpHjWCcXQcwHlGr+xzlSPkGVZZfUDyComBoXLLvJzSNIYXpaODr+9BadJMzoEFzAQfTTdsf2lqO8ZQP2NxR8dK/qBtlzgpbjseaR/2L7nj3MRiJEkXBcg6JW9VlZaqN1tvlgwsxHbsgkU3rqiyU4laAzrrYBSg+WLeCWQ/1OFSAuq36XgrktKWh3Nh8Itu2nAFfUpgnAvulcI9Fbe/KWsR/jDGSCIJey8yPnI4CXYUpQGrC4hqAIZW5MOy6LoE1VrztzajvFgkAGDwxMa4uzDdhR5IGtW1Evtlbjw8jWFXR+nPyjgCZ8Cg+KTlL6EwIctZRBY4Ea4DprMT0C0HU9NGiXwDSAt1XLyB5hRVhcadrtC4yLHcEyk0diyGIgg3EnDTFm3+1mpAHX8JkTUel3Re4tkn7xbuV3h9+D6kBTjISuvcYB4y3wd2iPwbWhrhT8G7WuvucIb4Ym2LahZ6FE5JuCy8H4jbX8uM4JCJli9HLTzyxTLNAUjF5s36j6KT4c9m3n1CKB3HLugsBiRvPKzUDcbFc0l+W5Lm2vISaPCBERQ15i1j7QBuyUYIm4uUAYD+bKk1e/ILRPVAUgkMJeAO4YG9uFNgaPh9GMZ2i2RLkJXBUNlcIt1O0qhhmLykHqYRRYQO0yj0pJONaW5wpAIUyTbME2ZChZkciCgsdmoELZENnTQKTCnNkCx8Ys8Rpl0F2u4JC2CWeA8ZtpZEE4kq1atFJEP39DTEzIAWPg0tPIkWfkK0yGlokVW0JCGWCYjfDgBrkSrMxgHPi9HgVtGQIBDgw1NW7500w72PiNiyVItBs8hZ4Ut4bl6qhiCLFL8KH4qUD7AHw4ejSpGIiRpD7dl5ODq1xCvtkK0H0S4GxrK4/5IcBAhmQ/h8rJ5MbABu/DxpJGjVCnKBIRQvRlaDmgiPHjI+bZOa0yz8OqIphciTPjpQaOvr68zj0BvYigcyGtEBWgewa495+ixSlk8yV4d5mxDJ2ibOSy3YaK/yxHdZaYCYPspll1hxTqe8AFaLZBkWG9GvrqUzKDHPifjgi8XGKtFKwyTbGIXYZCRCyT8FTKiG7ps8FUK+GxhXf8B7GItN9QxSRFjxSUFHMaADQDw8ezSs8LEeVku1WePhMayRnyO0x+PmGrqRqd7Ihsr4mo7vc3TGIbKhNAHg6q2ozxF6IhQYS+LRIslS0uiUhE4kfh6hU3rxSpHHQwNhlFPsg3gGuvgAsxdPzdUyXgxFB2zqofRnPJQoOVR8KF04lMZh4flkGxWBZLQK59VSvlgZDQtQ1sa8tC4EbNSbhcbGPGweh3q4qK8JWnWM6vpRD5X+FUyFYhTa4wY+ikln1CBHe72lUeiMsh/GQmH8mgCBolAonTHU0b2cttrkiXtkEj28OVOMPOiuj/vJiAQRy9gZ+zgaB+ZaoisgyVxL3jzAvnYyol+HW5Fa6JlVZnCVcXHcMxa5Dk173fg07NH4GkapYsRXmXY2Vt43Chsx0ZfnTdo2pS0sB1hl3jy9pOdiLyKcnSY468yrY+HjsJdhXfjcXi0yL9UUUj3n/uWaALTHL/wNdreIzMLX8ZmN2AY13XzzvmrzwX262T/fECDtIAlff4e3JVaQozOeN96AnIw0d5x+C04vlQmUa66Dw/sXBMRF6bCDuqVTb/wLo7nOYrH+v4LBPKOhGichhbVgNLSoxloYgrO9Vjtrhsz1Cq9GP94o14DlybydGi0Frc5TeC6hZs8vhiZdb3kxrKfSWoEyUIYP7T+irUO8vxgewZQ+9I5KZOnNdEPBjcAIN7/33zHZEzeeeDKapVlPm5xsJJ4sZuxKYxppKJpMxJMJPZkIXzKTCT2ZIE5g/L5mMnL9BsQpwpduAWqA+Y7a3NanIE7dMhzdJIvCke7T5k+DtvkACNgJOBN1HGhDx1nR2U1iu5hzjD2lffQ27XFOkaJGvm4FosIBEwO4PoqFQC5nYFeFE+egS16Gooj5g3wUbh3l/fqexHvHdE2Fs8pwwI6x0UCuYBL4NV4F8m27jEVi4Zny2NgYdHuc7BdEtge6LaryRTJZgEJtolCFsIDwBSoEUXkMMyWhezyFMlOo6hRqhim0vyuwUIdherGC1HJM1ESTIK+0W0rXUc0uwrLDNesRbQpA4ig0rCh5jZJVm3Q0CLBP1oLxvCB+A5GcCBhwDrMIBDJ72a9bcEDUZ6BIzOd9oyXURCnkowjn4WMT5xRpCxIVkazIuIKmrtYtbeTWGnUWGBFTR6NuHLtZiGErwnC/QYRD9jsCSwYvyY8AbEqwaPqaKB+ihAY4oQmsPVoBEtc4BlZClGbjOcuL5jCEmNPpFJjzhaEy7c/SPKiXvE42xaLqGIaLQIcCq4bTQszWaW849kGCpggaxcUCC/VDNICi+aaORHMEVn+tFzkiZj4i3rpYyBP7QC3asI6H9+GR9YFh8E5iKRy1SuIsmkc0FI1a/e/iDHd9+N/EGVA6rCbpsN1rny6GpqSGv7zviFFb9IpQs2xg3muKp5OMM1xsYitAWj0MeN/aCv4o1GNo0YF2mDSYpG3DjDBvPZ8m/7dhKlFONVk3yLlQmZZlkOlgGqPi7RCn4SaeZOnwXKAtTQvLi81uq0hTI11c94f9xaRfuJPTZhjMopCeFGa1JQIROtM9tMp5D3YXJBjSiWMAS8zPpszPkvNLytMJ0sW8BTsITIjwAsdHoaq3Nvgw4sYCOmgmS5IW6wKFpkKT64ZcR2NFHx4B8GHuagDqaQbVo9kYHsgQNcIISPuUG2SbRHkkP0tbcIkBM1MHZGZAOx7QNgPigcqlPD0Skm4Ktw9AxudlGRS7KnbhYUStiHCKRxtsZ0VhTVxPQLhT/ZRjrDGGuAwcHAkVq6Z81VdQRWIvZvLpZZGNGeBRUVW9Go+70EGd9eQgjdgGx/NKJ8ecIU29cA/PI56cL+/TJ0cZ7doEKXEk5Nfm9QnpfcVYSBVO1mfV4avNQn9UU28wiuzGnKkcy6jIJ6oz3ilxDGyqYlgIn8WZakdBJqX7m8BuAIOJGDypmrUDCMZ4TmeVw6yYbrwHwwqofH4QVD6hx4IW5P4l/6KcTsE6wWyd/+GTkcCq8PDYB4CZnM2m1xT2pq3KsLVHXv35vz5+4Lu/K3vHBKgF/IbwVXSyCdy2hLeSh6lSzSJLKMXViX4kEOTzqI9zuPRlFbr2fg11vL6CV5Atp8GF65jVQJaZoY3ZiQVXL+2+P4KlLQ1/i5cjPHzkj+H6RelvyAoK3Yc33go3msPn8HJIhK8dgOuDwt/QmxU6xnR0cpKNhke/l+6DyldeSZdCp38Mim/Q/buP0f17P+mVwpr+MWx44Vko/2lDPxTvfhWKP/Oo/3c/nSmFf/mTZdCJADu2rws0oQzXcoznzHR87KpQjIfOrs8TW32a7QfRL3WP6L2RKa+MKHTUHNVJJqFXht4BYD1ArEvjH0YqGMdIrsBUiIN36sxy6Jw3PkeLfMVaUKPLA1UWmLFEoU/Zb9JuTYtB9aKNhGiBM37TQgDDRVrRvCOaYDZIfK0EcB2a0HHgMNhMrukkLJOITdAKhM6iOFgdIo+ZBXRkA6tEoZtvWvRngFQspG9mhD2IEUzLRFAOfgIGAEZMTr0BrR5QhgKyKQyNEK5HKTochHd9HAj6LO0GDB+tVr5phQ+Y2jOCOxPIJbUwo5wVxEi5mEvjqXgD9B53PIcnBNTeXFbH40ATy2WAIYJ5xPNQdoFdoqkURSq9AZBRLkibTJ4HaWDJSJRO4OptcfuzqEQ6FEeXNCuPTjSOQksCFpxdp8N7KfTcTxuNhvPfBssB/uevgavdSy/i2Fr5mpwEvZNLLTA4JVciphFGETaUw4bdGLLYhDo7UB0qWtCGkhSp3y2PYVItrNKjTcZkE3xrSmAe865cCmXgOk094ZF95ER+7RbjRE6hWV6RQk0IdBGvAdlJTB4VY3RIaIeFldPupryNBqYiDgxSqyH8S+BB4Zc+gJnvTSEoz3ABiZlQ2LR405ocFOZPuRt+Yz9xvCkNUmuGGRBvOQePghvP9hDOJqdPgNlUvIfNhUt7MXxmv1aaUA7Dn7mk9AGel4gGFP9wdQEjcPGBYuA+KM09rAtK6U7ZDJdUpwx0f/LTWjAG+nYLdCWH3nm4cajbaeipLkmviODGDs2iEP7PD9DyoNxuLDyHXjnsYZgM5/QwOPPhmpL2MPGqP8QPvfrIm0A39LDeB7nWHGGXOHmol1EyWnhXRUtWHj5BpXodFMBI1nKjyfLwjGI4h0qoyc6HG4/v1wKah3M7RDsxhwLpr5y8ZR2ii0p69RyzhG6uaGX25xZP6Uif0B5LBdRO4tDVfso0UXJ6BSn3YHa9jJgC2yXSMRhZDsiShDaUqT8QdTFnJ14PcZFRgQJWBIsrsEugIxJnc0v0zh8JYUWvUyjgQiy2NWxkOWG6L2uRtYHe1HVG2wRll973C2zThQbSZrmtTRm0SLEBM9bwptA3RXRT4k2pb8ropsKbSt9U0U0Lb1r6phXdtPGmrW/aIbAHW6dz47LyEnikfhfOLuZTeOC8cGJX4IUfOXj/02xXuGfvfrc0CodW68IpbExNbQQrGgrX69gz+lUZxvG4R3NsJAauwv03RopEgLY0YpGYOvKcYpFeGpyCynVkyBMqVcTQ0CObk1pUWKjGcIz2sX562XEsq92F+mncb62hCS094LIZYTIvgKAdCuwbNCUkKR2CE8izgPkiVVQJhyPhEKHkmTaUNyDrTnYCOxP7xM1K96dXCywQflpBplEw8m6FB1CPeocOlKDXIDxkbtzhakX0GCshV0RjR78vQHE3i4LdE0YO70GhKtdQALeo98/BorHms6oRmiZ5EfTvSZ6864RvVOsgZcLfVasCPQSlPIx5g5EtNiLRQsOvHl/O1AaH0bRDwrCNA2TIcIGBvTxIvX5ApwOPcpRCPG9rMY4vnTrh0zeZxVvaiokHPXqTHtTywBaZFuoGRPXnbVJKxkwqFQp3fCVTt27UeaZIKorUpeoKTSZlQIpO5KYJ7CZkPFb4OGjQUrPv56E4VxefiYtrZSewKiu88WaEDpkyWOEbiEs/wYBRraEiWvrvohKysXOp1Ayl9fiWsBW+WB152iT1uohQKD2f0vM9/pbzbY3n0zNn4pldmtnyNP2AWd5Lh5wwJTWmgKdY+oVkmcRU1fmr31GmjmT0avIHMY9ajh1T4cQGRWIbfWrAkvG9xhwS0U857Q963JwxoARh9ntxqLNmtEMOyMEGVQJjrDAs+gjpJRmB3jlNPqLqzGPGmWfjM2P5yAOUGBnPArkZUcKHFZ+KEsQA9lX9TR5AaGlHsUX6VYdYbpBv6X14ubo70/asobpn8/RGWXqj7rjlrTbq6nijtsaEobdscbxlAW0Zj9QlUNnWUtJ2AUQ8CsD3UbADWD3mpQJzJx0ct4JTjjTHnOxGrTHxqsaEJnL4iNYJeFKHMYH3hvCr2MinNnp50BeQidGmsHXeU0LIWFuj+IIgYNxIFiv9Frwum8BlDEVIzgCjuT2GmptCzQ1kQBP53xOKVSO95f/0ByiyUkdBRhTLWaZH+JpeyZSHeuk9cgOA0GqZSKplFHwTRi2jLAFSyySqZRZefPTMoOuZ1DIK7qNHzUK1LJFVYELuhZC+coDKSRVO87mAWP8Ssf7l9TCXBCAvahcbKV/TEQrCSk1Tf6d485PoxGwm5HHKvMnNcyqB3+OwQ7Zz3Oev9HZPRbsZ5L8CeRHqHtoXo46fAHMm6IBBn7hzTiW0WYXarEEofnQDv7FAKFRQtEwMDBf9jF70VLeu9w82GnbLiIvozmiZ4Mv/abSMKRKCes+odtZzTYs67Q599nbSZw9WOuUfRL56jJZYIJxBaMceeSvpq7eSvnor6at3yX0I2PXQV++RE97WvvrEaNSNT4uGgMUHYONuWnEcSEeB8BVTtCQuI5qJScuJk4dtXEQqdEdJW8WXIR0YNYcvypOX3wWdOuHl54JUyGhQhe8nMnxBVuf02OTqxws5/R0vAjZy+rtTnP4psnJ10AFNXbCW8L3maU5/a4rTP16P9tujG5YljTqs5LgJKuCSxITEBVsYMQJGEwEEU/FEVACBAET263UQkBgWLpD3BRABlhwRYJAAgVUxxqMkvQhvM0dHhKEXNOQRUdwgShyHKFvDYBbiTEMUCFy0U49DFDeIYjMiR7/5o+PCDRhgQlomj6KNuMVdo3w44tsxZpDOAswExo1PaQy49DETfFclip/QVFMO2t/zqcGH0OT1ohs+ViMq3Ljv/H7tmKwo8hX9YTkgknJAMN2DT88gOS4fZHrCyL8hS8Xzz4vC4xdOzwT5N6SBPPmh49JAsrFNDka/9w9TMakz6UOTSfD/ETL/g9JqZsDnAPqLJ8zxWEeqiYn6xTTrk0xqxLfmwF7xIrpGk2EqXS+BHdC+WlDVqFP4EmZzZKf2a9o/U89vziCSoOdPJMgkvcNg/mm9DrqDrntaVUXz845RObSQ888h5R8UBIrcuiY8YumveJCDD78R4UaLRv8ksMTn6YM50SsrFPMHDiW5ZA7aAahbkoMjlDke/o5VX5nCbpalgJWlPPRVhL9Fz7zywt/giJKMLPRM0Aw6aM4Dl/zcRu2DNgqRuPSO3jjGLhjFLhimEyud9QTd0LgEzDuaBcFQzJsBeIBIoEhClfXEcMeQKwldnQSEMgG5SKwoCS4pCRpYUIkLY28CJphOXMvA0+iWR7o/EN8eWzgT/AajRJCqABIDXRNgmuTQl6bdTrxE8cHYS2UMYIU7DJSgfbOO/rhYKlCggKB/ZqJvLMvJ6e9uJmUBn6B3EUmfgGvkp0HvC6W/oZ/ZfGFnY1aYR1DBYOsxa5yUVh3fyzjeWp5LR4rFNOPcDp/6sPa640ZIIIwaTz8sUWCgb8day3LpTNaLinHz5iy9kG+o1wZ+BGpHL0mhbJ9WXo9/xKs+kgDiGO4ufnuOPp+g8RROnAM2Zm2RLBkxMAb3j/DNY9msfo/qGNMtBQBDf20sfkqGt+EXTzADAlS15LyRuYzUK2do2ZC11kqNrIyHYx6FGQ7xddmUnjQxxSGEhd7qdTCHHkHJIO92whtGw+F1ic4x5O5xcD6GcDpJOJ0pcEZ6dHwjysFQJj+jmCM/GYZL4Bh7a4UBnsebTm47nQrnFUN0m0EpVQzSZzITjbL0Pa7fGdIfPdMt+k02/Q7VbbwaaKUXOXAP6V0NckHKRPhUIFdQxBVU0QxewiQ2uKnG6fzV0rdIGMU0BcY0KciUjFPGEU4aW0c4Wcm/CF9wwACm97U/JPJrkttM5Hcq6Go66MlgbAy61KDL40FPhmNZNRzLqrHfE8zX+Z8wnfCm4VGcIPr7dSGsONMf87ZPo/f12NoD32fvpFeRMJ6CWUZILUieoSqh/xw7VPIOXm54/315i8JR4YtsGBO9y+FegKy4irHTGWYfiBJ6eKB1Z0n3m9YDpD3FutdOfuPZVRcGTk5/OMy5D6b7e3YO7aDAV60QiiLdR0ERzShPODK5msP0pukjyGn9jOsh2aGAO4EEiK5S+r4eIQBkAkbYoUrp9Lf+nueh87/oOFQzStd7t4tkSqmYMAY1cnkdxEQ95ujHKcxynG9J6ObnZ2hGh4iIXoOAWkrrsJQLRV6SOCX1nZgGv4LR6/L0late/dq/FvE8iNwuOp1dYhYjwwdSvdqJgg6TLDM6XnhkBpWLFD1q/cZMPoLI/3V8wu027x/59JyqqopHa38R156auvam/VOyf/8PdtEJSeGTH4+zf5XJ/n1Nj0DN++/EZo0QhQhZwawToSPPqs4ilvAAsum7xBIewKkrj3LcDQK+IugtN6RCemNAZwzoFHRQP/Lkr1C6BV+t1JEcyodikT1pojmW1jks/TYgekvyTpEyfEhhwXx0EoB8PekpspznYcMoZk2BYoQlUHnwIcxkzOlMJpoPDXB3XDNuO0iV9QuluhMqQPq9MB2To9HhTFKal0XPnKC3yc/E97Icyo6AY74pfpWblsnNMk1MXsZ6D33twfM+FUimv1n7VHrX2LZVO3dcsXJsF37b1mdp+JuD32743Ta4c+fQ9mDrO4Z27d5Z7unZPXzd2OC1zUu2BiPDweBwsLV3bGxrMD64c/cQfiWX1cOvIm2HvppLP9EYm68t7xgZnj5GsHXTyPCQGQPAGBsce8+qXeXtqxCsaweHd2wr7Ri+CoG7CWCbD+Mdg4EXwTWq/wrqC828GXO14NeGX9fUHVP2TT0Fv+lpfTzzvG3q+Jtl+pu/tfAbAUef7yXwxgav2zI+tA2A2zZ47eC2HeX3BCPjQ2NX7hy5Dvo3cw2fLTQ8fWMj11xQvrILUDYydsV7ykO7qvDgL6jlbAjb2NT7s6bVT4LflSsZexjGF38Yflmj2RPcmyb43TG8fej6YGR3ORi5MrhiZPfw9l09QfnqoWDn0HCwY1cQXAFNWNcd4Q5jr3N8EYSx+cIn2Lb2BAQL/oRCw9SY2AvEwQKm9yiAnwiP20bGhgiNV15TXnXF7h07tw+N7QJcXiv0+KsMHUb1gsFF8N708vTyIHhv8P7g/c3p5uVL0pc0JvCDtHHZjJMM774Gxv8hjIdrHzL0Wri+UCi0FFoLbYX2wupCR6Gz0FXobim0tLS0trS1tLesbulo6WzpauluLbS2tLa2trW2t65u7WjtbO1q7W4rtLW0tba1tbW3rW7raOts62rrbi+0t7S3tre1t7evbu9o72zvau9eXVjdsrp1ddvq9tWrV3es7lzdtbq7o9DR0tHa0dbR3rG6o6Ojs6Oro7uz0NnS2drZ1tneubqzo7Ozs6uzu6vQ1dLV2tXW1d61uqujq7Orq6u7G0Dshum7YehueKwbbmm8R3gIDP7yCdqN0bFr545tQ6uuGbpm29VjgJMXpcbxJebsjA0OXzUU7CoPjpXN1kdEoluuHBkLaAi8BbRyVfnqoF5pejgVrvl4jKHh7WaEd8F9P9Gun9dtNNOuYLCsKQ4eogq7HvrOgb63wjU74zrKY6uAtHdsH0TiR/Lh/80/LLz9JuCrbeJNf+S0H8o0ZBSH9j44+wFY7sl4ZLhmC5esXLnyMmQZ0WbAQZxyaLG0lbGfWz6xsWOWRtsaIHU86lcMXbVjODjjTNqNZiwsCa67Go447gGwV3w2sH1idSvhiuTTauvtisbAOYdHysBRtl09OKbnha04PdhRxqYdw7t2bB8KgmbibDA+QhTBsx3GOhWuH4ErstuPwtVOjH3ctu4Gvj+yfWjVtWM7hsuDV+wc0tLpCDx3imHd8xN1JPsO4mvSsmxbOLbrpOrS8715mcasX5OtVb6cNeuk1Bw+VzXwebLRaeLzxaI5gVwmV3greUG2iFZ+n/iM+Kz6nPt/xW+t34k35GTq89e/56Zb7i1c9K6bbj4w/3/X1A5s+O3rK1edfellW362/5Zbb//oZ/78q49869vf+Zu/e/Hnk0zVzVrS0t7Zc/qZ/edctv9WaHz4q498+2++/9SLP2cqW0OtPaf39vWfc/n2of23f+KT3/n+U9m6JXCr/6JLLr18y/ahW27/DDzyre/89MWfH8vW9fZvH6rs/4tHv/7YD5899qt9H7jp8Ke//ti3/vr7T/34J+vv+Nr3vv39p/o3bb7o4su3fPjW2/78i1967Bvf/utn6+bMveTSf/6XNyYr14z+3U9rFg2PzF+w5f03fOHBiUcenTN34aK+dZs2v+vdl15+w8RffuuZHz5/7Fe/Gdt1W3n3n5y6ctV9D37psb9+6tmf3rnmY3cUblv0v575/uSmze++xHFr/dNWvfLL4ZHOM89e23vg9vOv2v3Ed57+wXN/+4s3JlmwJb/3p2rv290mZdfteaCm8jlrUWpPk5zncrVKtStHcsd26tLn1s5yLnCkmp9OSVc6Euk/oyzp2bxmtrXJaXIucoQ9J3uueptcIbmqs2szPWrBKVuCa1TxlMoT1t6HZKO993fyYmdOqiFVn6nPFO203Whf7Cyz+tLLVUZx2eItV422JysPQNOqlo2yctg9Q9bKM5wud5m1d7KuwV1Vt0LmanO1lZvV3o/N82bfeNBaZZ3uiJqGVOXr+XKm8qPGjFWZtCo/zfz6k7IztefS+sqX3cp3rXTD6TJtd7l9bsYuewvlu9XFqcq+hvnpOakNqvIR+3OHM3NVyz1qz49PdTKWVfm0v+c3Dg+W2tB6i6p8XTbJ2iyzwbTiSliOI1w3JdKWJ2qUz+vELOukuno+W8wV87LzrQXuYl5UJfGgfFQ8JX4gnsn8MPUj8az4MT9qvSB+oV4SrwTH1GsCCJVnTjv9rE2bb7v77j99701/9Cf3/sVXP/jntpPqOPOsC//p6R+o+oaOzgsvmvjsFx782uqjsz704VvvjikRCXHT5u1Dl37xS03zHTft1c/t6O65/zPP/W2q88Dt9zvp08+6csdtHx3Z8tgrv3z3Fa++PnnnJ1auOq35gk8euudTh++7//NfffRx28vMXtBzdu95n77vye8dcuY15k856+xfvPzLyW99WwUnn3Jqc1tXz/pzNpx7/gUXItFt3TZ0ZWnX9e+f+Mjhzz740JGnv/Dg8MgfXZ5/ryXVCnml5KtWVvYukC2189Xi1EJrmfV2VbO08ll7sVqsmt12b9Pb9nSm5qTdhtN7u+U2N1WYY+Vkk8XXdKkBa5VKOylnTXCayqQ6ZI/V6KiMc25/Z1u2zVnppvec+o5Nze7SOY2nzq+fm9oEE7w9O89J2+vd01K7vbPDpfbpVto+z+aWL63KTVcsXO+mK5++PN/rpe3sST12umO5mlv5yhnbz8+sT6X7epvWu+dn+/c4fekFcl1/p6xx03a3k97TMa/yJV7bmt33iSt3e5XHP7JhW3b/qtt+sHfdPV/Z2+0sVZfap6b70s3WSXsfumRoQHU7dWuQBj72mrv/R0tT9/5iT9sKWafcPTd/WJWsrEw5/ke3rkuVz6j8c3qXe+3svsqd9ZmLUvMqH9qzTn5gbe3s/ecuqrywrPLDFbJRiT1rFtX1WHz/0cq/LNmg0krsq3v7hjMrf3WGzdUFVlO72FOzXG3PXJiufKFrQXa5SgHd25U79z0Hi87KcuZiB05RbUZ1wWKa3fymPe/MzJaWdFILpGfZ6bTtAletfPeU9H77hAzbXOm/s9A8ezTjs2a4DqBKnKhfBL9zEvV3wO9ZbKoKgzLw/JFrhlCFjVVnEvdbdl+7pTxC6vIW0D+mPbcYZYFkbJ8K2O3WVnbZSYfYrLnBokywddEvlx9atrQQLB/59NHl4v6tKxb+dutK9kbQcffk1o7f8Rc6eDrXuTj7Qufnaga7VzXc012Y/8K6f1qY23Cs+MLmzSO5cz/56D3nsqcGzxv6wT3nsR/n3sGOvnB+4YXBC77ws3sufPqlFy4M2PBFx/jkRexasDpWgEIg4B9f7xVm+3wImJwQXJ3MFzZd4vWkUrxB8RTwBGuZPMNd2sCDTnhAucDMnLRYwHvwceVCl7Ro5EJ0A/NQqDzwhUJyD+sWdOD1Yg6wlh6cC3o7Mi0W8tPh2Qw82QzDw6iwkVw5wqNRESSYVGB9vugW1VkW8PVccRicu/w8LpyMewWGVOxzRBNpN501HGa0PL44xa9U3AagxDyhpK+yULR5LQe8ywViIfxbAwa6y4WX4sDS+W6R5+NSiRS35U8ACQCtgyMK104LXljUogpQt3hzKgOWLXSQXZwAkT2uEHdInuUOTijFt9cw/s0ck7fwrQGzdwimeDoQ5+JndgD2ecLiHxONs7L8VHeet1IWOKLsNP42G/WuDKxrFW+DUYWwYN1LhctfQbRxUER8H60X/jP+xxaTsErVLBX/MxifiY97Leq9vKN2CawyLVtgRIefKRdb3D2LZ0R7Ck4b3yIRkTY/xKU7m7DK+Rxe40jrmy4uZC5i1MZNwg34R4DLhmuTuMDFO0VOD/MhCRtqsRQXv4H9AGrgB2A2xYN0s027ZAu5EpDNHEAGf8ccAARG+R+2xFEBg+txKg7rALnG+NnqPCyvFHMZrFlZriucheqgZJ2q1eU1fI7Fa2GkOhrFAorlZyrmXOOwrZVj/w+H69KhvWcAAA==").unwrap();
        // opt-level s
        //let contract_bin = Binary::from_base64("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").unwrap();
        // with secret std
        //let contract_bin = Binary::from_base64("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").unwrap();
        let contract_b64 = fs::read_to_string("./wasm-sample-app/optimized.wasm.gz.b64").unwrap();
        let contract_bin= Binary::from_base64(contract_b64.borrow()).unwrap();

        let msg = SaveContract { data: contract_bin };
        let env = mock_env("creator", &coins(2, "token"));

        handle(&mut deps, env, msg).unwrap();

        //// Run Contract
        let msg = RunWasm {};
        let env = mock_env("creator", &coins(2, "token"));

        let start = SystemTime::now();

        handle(&mut deps, env, msg).unwrap();

        let end = SystemTime::now();
        let elapsed = end.duration_since(start);
        let taken_ms = elapsed.unwrap_or_default().as_millis();

        println!("taken: {taken_ms}ms")
    }
}
