extern crate wain_syntax_binary;
extern crate wain_validate;
extern crate wain_exec;
extern crate wain_ast;
extern crate libflate;

use std::str;
use std::cmp::max;
use std::io::{Cursor, Read};

use cosmwasm_std::{Api, Binary, CosmosMsg, debug_print, Env, Extern, HandleResponse, HumanAddr, InitResponse, plaintext_log, Querier, StdError, StdResult, Storage, to_binary};
use cosmwasm_storage::PrefixedStorage;
use secret_toolkit::utils::{HandleCallback, Query};

use wain_syntax_binary::{parse};
use wain_validate::validate;
use wain_exec::{Runtime, Value, Importer, Stack, Memory, ImportInvalidError, ImportInvokeError};
use wain_ast::{Root, ValType};

use libflate::gzip::Decoder;

use wain_syntax_binary::source::BinarySource;

use crate::msg::{BatchTxn, CountResponse, HandleMsg, InitMsg, OtherHandleMsg, QueryMsg};
use crate::state::{config, config_read, contract_data, CONTRACT_DATA_KEY, set_bin_data, State};

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
        HandleMsg::SaveContract { data} => try_save_contract(deps, env, data),
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
    data: Binary
) -> StdResult<HandleResponse> {
    let data_u8 = data.as_slice();
    if data_u8.len() <= MIN_CONTRACT_LEN {
        return Err(StdError::GenericErr {
            msg: format!("data for contract invalid length (not big enough)"),
            backtrace: None,
        })
    }

    // TODO: Authentication

    // Verify
    debug_print("WASM: validating WASM");

    let wasm = deflate_wasm(&data_u8)?;
    let tree = parse_wasm(wasm.as_slice())?;

    debug_print("WASM: loaded WASM module");

    // Validate module
    if let Err(err) = validate(&tree) {
        return Err(StdError::GenericErr {
            msg: format!("WASM is invalid: {err}"),
            backtrace: None,
        });
    }

    debug_print("WASM: verification successful");

    // Store
    //contract_data(&mut deps.storage).save(&data_vec)?;
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

const MAX_RESULT_SIZE: i32 = 1024;

struct CortexImporter {
}

impl Importer for CortexImporter {
    fn validate(&self, name: &str, _params: &[ValType], _ret: Option<ValType>) -> Option<ImportInvalidError> {
        // `name` is a name of function to validate. `params` and `ret` are the function's signature.
        // Return ImportInvalidError::NotFound when the name is unknown.
        // Return ImportInvalidError::SignatureMismatch when signature does not match.
        // wain_exec::check_func_signature() utility is would be useful for the check.

        unreachable!("fatal (1): invalid import function '{}'", name)
    }

    fn call(&mut self, name: &str, _stack: &mut Stack, _memory: &mut Memory) -> Result<(), ImportInvokeError> {
        // Implement your own function call. `name` is a name of function and you have full access
        // to stack and linear memory. Pop values from stack for getting arguments and push value to
        // set return value.
        // Note: Consistency between imported function signature and implementation of this method
        // is your responsibility.
        // On invocation failure, return ImportInvokeError::Fatal. It is trapped by interpreter and it
        // stops execution immediately.

        unreachable!("fatal (2): invalid import function '{}'", name)
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
        })
    }

    debug_print!("WASM: deflated contract ({} bytes)", res.unwrap());

    return Ok(buf)
}

fn parse_wasm(wasm_binary_u8: &[u8]) -> Result<Root<'_, BinarySource<'_>>, StdError> {
    return match parse(wasm_binary_u8) {
        Ok(tree) => {
            debug_print("WASM: parsed");

            Ok(tree)
        },
        Err(err) => {
            Err(StdError::GenericErr {
                msg: format!("failed to parse WASM binary: {err}"),
                backtrace: None,
            })
        }
    };
}

/*
    Allocate memory for array of bytes inside the wasm module and copy the array of bytes into it
*/

fn send_byte_array(runtime: &mut Runtime<CortexImporter>, bytes: &[u8]) -> Result<i32, StdError> {
    let alloc_size = max(bytes.len() as i32, MAX_RESULT_SIZE);

    return match runtime.invoke("alloc", &[Value::I32(alloc_size)]) {
        Ok(ret) => {
            match ret.unwrap() {
                Value::I32(v) => {
                    debug_print!("WASM writing to memory: {v}");

                    runtime.memory_store_bytes(v as usize, bytes).map_err(|err| {
                        return StdError::GenericErr {
                            msg: format!("failed to write to WASM memory: {err}"),
                            backtrace: None,
                        }
                    })?;

                    Ok(v)
                }
                _ => {
                    return Err(StdError::GenericErr {
                        msg: format!("expected i32 to be returned by 'alloc' call"),
                        backtrace: None,
                    })
                }
            }
        }
        Err(err) => {
            Err(StdError::GenericErr {
               msg: format!("failed to 'alloc' memory in WASM: {err}"),
                backtrace: None,
            })
        },
    }
}

pub fn try_run_wasm<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
) -> StdResult<HandleResponse> {
    debug_print("WASM: start");

    let data_u8 = deps.storage.get(CONTRACT_DATA_KEY).unwrap();

    //let data_vec = contract_data(&mut deps.storage).load()?;

    debug_print("WASM: loaded contract");

    let wasm = deflate_wasm(&data_u8)?;
    let wasm_u8 = wasm.as_slice();
    let tree = parse_wasm(&wasm_u8)?;

    debug_print("WASM: loaded WASM module");

    // Make abstract machine runtime. It instantiates a module
    let importer = CortexImporter{};

    let mut runtime: Runtime<CortexImporter> = match Runtime::instantiate(&tree.module, importer) {
        Ok(m) => m,
        Err(err) => {
            return Err(StdError::GenericErr {
                msg: format!("failed to instantiate WASM runtime: {err}"),
                backtrace: None,
            });
        }
    };

    debug_print("WASM[04]: loaded WASM instance");

    // Allocate a string for the input data inside wasm module
    let input_data = b"Hello World";
    let input_data_wasm_ptr = send_byte_array(&mut runtime, input_data)?;

    debug_print("WASM[05]: wrote to WASM memory");

    match runtime.invoke("run_wasm", &[Value::I32(input_data_wasm_ptr),
        Value::I32(input_data.len() as i32)]) {
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
                    })
                }
            }
        }
        Err(err) => {
            return Err(StdError::GenericErr {
                msg: format!("failed to call 'run_wasm' in WASM: {err}"),
                backtrace: None,
            })
        },
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
    use cosmwasm_std::{coins, from_binary, StdError};
    use cosmwasm_std::testing::{mock_dependencies, mock_env};

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
}
