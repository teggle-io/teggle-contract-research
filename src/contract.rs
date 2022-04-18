extern crate omnibus_core;

use std::cell::RefCell;
use std::rc::Rc;
use std::str;

use cosmwasm_std::{Api, Binary, debug_print, Env, Extern, HandleResponse, InitResponse, plaintext_log, Querier, StdError, StdResult, Storage, to_binary};
use cosmwasm_storage::PrefixedStorage;

use crate::msg::{BatchTxn, CountResponse, HandleMsg, InitMsg, QueryMsg};
use crate::state::{config, config_read, CORTEX_CORE_KEY, set_bin_data, State};

//use secret_toolkit::utils::{HandleCallback, Query};

pub const PREFIX_SIM: &[u8] = b"sim";

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: Rc<RefCell<Extern<S, A, Q>>>,
    env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    let mut deps = RefCell::borrow_mut(&*deps);
    let state = State {
        count: msg.count,
        owner: deps.api.canonical_address(&env.message.sender)?,
    };

    config(&mut deps.storage).save(&state)?;

    debug_print!("Contract was initialized by {}", env.message.sender);

    Ok(InitResponse::default())
}

pub fn handle<S: 'static + Storage, A: 'static + Api, Q: 'static + Querier>(
    deps: Rc<RefCell<Extern<S, A, Q>>>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    debug_print!("handle called by {}", env.message.sender);

    match msg {
        HandleMsg::NoOp {} => try_no_op(deps, env),
        HandleMsg::Increment {} => try_increment(deps, env),
        HandleMsg::Reset { count } => try_reset(deps, env, count),
        HandleMsg::Simulate { count } => try_simulate(deps, env, count),
        HandleMsg::SimulateOther { count: _ } => {
            //try_simulate_other(deps, env, count)
            Ok(HandleResponse::default())
        },
        HandleMsg::SimulateQuery { count: _ } => {
            //try_simulate_query(deps, env, count)
            Ok(HandleResponse::default())
        },
        HandleMsg::ProcessBatch { transactions } => try_process_batch(deps, env, transactions),

        // RHAI
        HandleMsg::Save { data } => try_save(deps, env, data),
        HandleMsg::Load {} => try_load(deps, env),
        HandleMsg::Run {} => try_run(deps, env),
    }
}

pub fn try_no_op<S: Storage, A: Api, Q: Querier>(
    _deps: Rc<RefCell<Extern<S, A, Q>>>,
    _env: Env,
) -> StdResult<HandleResponse> {
    Ok(HandleResponse::default())
}

pub fn try_increment<S: Storage, A: Api, Q: Querier>(
    deps: Rc<RefCell<Extern<S, A, Q>>>,
    _env: Env,
) -> StdResult<HandleResponse> {
    let mut deps = RefCell::borrow_mut(&*deps);
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
    deps: Rc<RefCell<Extern<S, A, Q>>>,
    env: Env,
    count: i32,
) -> StdResult<HandleResponse> {
    let mut deps = RefCell::borrow_mut(&*deps);
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
    deps: Rc<RefCell<Extern<S, A, Q>>>,
    env: Env,
    count: i32,
) -> StdResult<HandleResponse> {
    let mut deps = RefCell::borrow_mut(&*deps);
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

/*
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
 */


pub fn try_process_batch<S: Storage, A: Api, Q: Querier>(
    _deps: Rc<RefCell<Extern<S, A, Q>>>,
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

pub fn try_save<S: Storage, A: Api, Q: Querier>(
    deps: Rc<RefCell<Extern<S, A, Q>>>,
    _env: Env,
    data: Binary,
) -> StdResult<HandleResponse> {
    let mut deps = RefCell::borrow_mut(&*deps);

    // TODO: Authentication

    // TODO: Verify
    // TODO: Ensure dummy deps are passed in

    // Store
    // raw storage with no serialization.
    deps.storage.set(CORTEX_CORE_KEY, data.as_slice());

    debug_print!("saved rhai bytes: {}", data.len());

    Ok(HandleResponse::default())
}

pub fn try_load<S: Storage, A: Api, Q: Querier>(
    deps: Rc<RefCell<Extern<S, A, Q>>>,
    _env: Env,
) -> StdResult<HandleResponse> {
    let deps = RefCell::borrow_mut(&*deps);
    let script_data = deps.storage.get(CORTEX_CORE_KEY).unwrap();

    debug_print!("loaded rhai bytes: {}", script_data.len());

    Ok(HandleResponse::default())
}

pub fn try_run<S: 'static + Storage, A: 'static + Api, Q: 'static + Querier>(
    deps: Rc<RefCell<Extern<S, A, Q>>>,
    env: Env,
) -> StdResult<HandleResponse> {
    let script_data = RefCell::borrow_mut(&*deps)
        .storage.get(CORTEX_CORE_KEY);
    match script_data {
        Some(v) => {
            omnibus_core::handle(deps, env, v)
        },
        None => Err(StdError::GenericErr {
            msg: format!("no rhai script found to run."),
            backtrace: None,
        })
    }
}

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: Rc<RefCell<Extern<S, A, Q>>>,
    msg: QueryMsg,
) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetCount {} => to_binary(&query_count(deps)?),
        QueryMsg::GetIndexMeta { auth } => to_binary(&query_index_meta(deps, auth)?),
    }
}

fn query_count<S: Storage, A: Api, Q: Querier>(
    deps: Rc<RefCell<Extern<S, A, Q>>>
) -> StdResult<CountResponse> {
    let deps = RefCell::borrow_mut(&*deps);
    let state = config_read(&deps.storage).load()?;
    Ok(CountResponse { count: state.count })
}

fn query_index_meta<S: Storage, A: Api, Q: Querier>(
    deps: Rc<RefCell<Extern<S, A, Q>>>,
    auth: String
) -> StdResult<CountResponse> {
    let deps = RefCell::borrow_mut(&*deps);
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

    use crate::msg::HandleMsg::{Run, Save};

    use super::*;

    #[test]
    fn proper_initialization() {
        let deps = mock_dependencies(20, &coins(2, "token"));
        let deps = Rc::new(RefCell::new(deps));

        let msg = InitMsg { count: 17 };
        let env = mock_env("creator", &coins(1000, "earth"));

        // we can just call .unwrap() to assert this was a success
        let res = init(deps.clone(), env, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query(deps.clone(), QueryMsg::GetCount {}).unwrap();
        let value: CountResponse = from_binary(&res).unwrap();
        assert_eq!(17, value.count);
    }

    #[test]
    fn increment() {
        let deps = mock_dependencies(20, &coins(2, "token"));
        let deps = Rc::new(RefCell::new(deps));

        let msg = InitMsg { count: 17 };
        let env = mock_env("creator", &coins(2, "token"));
        let _res = init(deps.clone(), env, msg).unwrap();

        // anyone can increment
        let env = mock_env("anyone", &coins(2, "token"));
        let msg = HandleMsg::Increment {};
        let _res = handle(deps.clone(), env, msg).unwrap();

        // should increase counter by 1
        let res = query(deps.clone(), QueryMsg::GetCount {}).unwrap();
        let value: CountResponse = from_binary(&res).unwrap();
        assert_eq!(18, value.count);
    }

    #[test]
    fn reset() {
        let deps = mock_dependencies(20, &coins(2, "token"));
        let deps = Rc::new(RefCell::new(deps));

        let msg = InitMsg { count: 17 };
        let env = mock_env("creator", &coins(2, "token"));
        let _res = init(deps.clone(), env, msg).unwrap();

        // not anyone can reset
        let unauth_env = mock_env("anyone", &coins(2, "token"));
        let msg = HandleMsg::Reset { count: 5 };
        let res = handle(deps.clone(), unauth_env, msg);
        match res {
            Err(StdError::Unauthorized { .. }) => {}
            _ => panic!("Must return unauthorized error"),
        }

        // only the original creator can reset the counter
        let auth_env = mock_env("creator", &coins(2, "token"));
        let msg = HandleMsg::Reset { count: 5 };
        let _res = handle(deps.clone(), auth_env, msg).unwrap();

        // should now be 5
        let res = query(deps.clone(), QueryMsg::GetCount {}).unwrap();
        let value: CountResponse = from_binary(&res).unwrap();
        assert_eq!(5, value.count);
    }

    #[test]
    fn run() {
        let deps = mock_dependencies(20, &coins(2, "token"));
        let deps = Rc::new(RefCell::new(deps));

        //// Save Contract
        let core_b64 = fs::read_to_string("./cortex/neo.core").unwrap();
        let core_bin = Binary::from_base64(core_b64.borrow()).unwrap();

        let msg = Save { data: core_bin };
        let env = mock_env("creator", &coins(2, "token"));

        handle(deps.clone(), env, msg).unwrap();

        //// Run Contract
        let msg = Run {};
        let env = mock_env("creator", &coins(2, "token"));

        let start = SystemTime::now();

        handle(deps.clone(), env, msg).unwrap();

        let end = SystemTime::now();
        let elapsed = end.duration_since(start);
        let taken_ms = elapsed.unwrap_or_default().as_millis();

        println!("run_wasm taken: {taken_ms}ms")
    }
}
