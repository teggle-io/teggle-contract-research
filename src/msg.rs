use cosmwasm_std::Binary;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use secret_toolkit::utils::{HandleCallback, Query};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {
    pub count: i32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    NoOp {},
    Increment {},
    Reset { count: i32 },
    Simulate { count: i32 },
    SimulateOther { count: i32 },
    SimulateQuery { count: i32 },
    ProcessBatch {
        transactions: Vec<BatchTxn>,
    },

    // Wasm
    SaveContract { data: Binary },
    LoadContract {},
    RunWasm {}
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WasmHandleMsg {
    DoNothing {}
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct BatchTxn {
    pub id: String,         // UUID generated by relay
    pub auth: String,       // a:secret1pcknsatx5ceyfu6zvtmz3yr8auumzrdt55n02p:<time>:<sig>
    pub payload: Binary,    // base64 encrypted messages to process.
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OtherHandleMsg {
    Simulate { count: i32 },
}

impl HandleCallback for OtherHandleMsg {
    const BLOCK_SIZE: usize = 256;
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    // GetCount returns the current count as a json-encoded number
    GetCount {},
    // Testing
    GetIndexMeta { auth: String },
}

impl Query for QueryMsg {
    const BLOCK_SIZE: usize = 256;
}

// We define a custom struct for each query response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct CountResponse {
    pub count: i32,
}
