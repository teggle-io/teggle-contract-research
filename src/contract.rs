extern crate libflate;
extern crate wain_ast;
extern crate wain_exec;
extern crate wain_syntax_binary;
extern crate wain_validate;

use std::io::{Cursor, Read};
use std::str;

use cosmwasm_std::{Api, Binary, CosmosMsg, debug_print, Env, Extern, HandleResponse, HumanAddr, InitResponse, plaintext_log, Querier, StdError, StdResult, Storage, to_binary};
use cosmwasm_storage::PrefixedStorage;
use libflate::gzip::Decoder;
use secret_toolkit::utils::{HandleCallback, Query};
use wain_ast::{Root, ValType};
use wain_exec::{check_func_signature, Importer, ImportInvalidError, ImportInvokeError, Memory, Runtime, Stack, Value};
use wain_exec::trap::Trap;
use wain_syntax_binary::parse;
use wain_syntax_binary::source::BinarySource;
use wain_validate::validate;

use crate::msg::{BatchTxn, CountResponse, HandleMsg, InitMsg, OtherHandleMsg, QueryMsg};
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

fn map_trap_err_to_import_err(err: Box<Trap>) -> ImportInvokeError {
    return ImportInvokeError::Fatal {
        message: err.to_string(),
    };
}

impl <'d, S: Storage, A: Api, Q: Querier> Importer for CortexImporter<'d, S, A, Q> {
    fn validate(&self, name: &str, params: &[ValType], ret: Option<ValType>) -> Option<ImportInvalidError> {
        match name {
            // Database
            "db_read" => check_func_signature(params, ret,
                                              &[ValType::I32],
                                              Some(ValType::I32)),

            // Debug
            "debug_print" => check_func_signature(params, ret,
                                                  &[ValType::I32], None),
            _ => Some(ImportInvalidError::NotFound),
        }
    }

    fn call(&mut self, name: &str, stack: &mut Stack, memory: &mut Memory) -> Result<(), ImportInvokeError> {
        match name {
            // Database
            "db_read" => {
                let key_str_bytes = memory
                    .get_region(stack.pop())
                    .map_err(map_trap_err_to_import_err)?;

                self.deps.storage.get(key_str_bytes.as_slice());

                Ok(())
            },

            // Debug
            "debug_print" => {
                let msg_str_bytes = memory
                    .get_region(stack.pop())
                    .map_err(map_trap_err_to_import_err)?;

                // cortex.v1 (example of module name and version).
                debug_print!("WASM2[cortex.v1]: {}", String::from_utf8(msg_str_bytes).unwrap());

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
    _env: Env,
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
        //let contract_bin = Binary::from_base64("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").unwrap();
        // opt-level s
        //let contract_bin = Binary::from_base64("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").unwrap();
        // with secret std
        let contract_bin = Binary::from_base64("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").unwrap();
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
