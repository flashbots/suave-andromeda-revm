use lazy_static::lazy_static;
use reqwest::blocking::Client as ReqwestClient;
use reth_primitives::Bytes;
use sha2::*;

use ethers::abi::{encode, Bytes as AbiBytes, Contract, Token};
use ethers::contract::{BaseContract, Lazy};
use ethers::types::{Address, H256};

use revm::precompile::PrecompileWithAddress;
use revm::primitives::{
    Address as RevmAddress, Env, EnvPrecompileFn, Precompile, PrecompileError, PrecompileErrors,
    PrecompileOutput, PrecompileResult,
};

use std::collections::HashMap;
use std::sync::Mutex;

use crate::u64_to_address;

// Redefined here to avoid having to import from external services
pub static SERVICES_MANAGER_ABI: Lazy<BaseContract> = Lazy::new(|| {
    let contract: Contract =
        serde_json::from_str(include_str!("../out/ServicesManager.sol/SM.abi.json")).unwrap();
    BaseContract::from(contract)
});

pub const RUN: PrecompileWithAddress = PrecompileWithAddress(
    u64_to_address(0x3507),
    Precompile::Env(run as EnvPrecompileFn),
);

pub struct ServicesManager {
    pub service_handles: HashMap<H256, (RevmAddress, H256)>,
}

impl ServicesManager {
    pub fn new() -> Self {
        ServicesManager {
            service_handles: HashMap::new(),
        }
    }
}

lazy_static! {
    static ref GLOBAL_SM: Mutex<ServicesManager> = Mutex::new(ServicesManager::new());
}

const INSTANTIATE_FAILED: &'static str = "could not instantiate requested protocol";
const INCORRECT_INPUTS: &'static str = "incorrect inputs passed in";
const SERIVCE_MISCONFIGURED: &'static str = "service is misconfigured";
const SERIVCE_REQUEST_FAILED: &'static str = "request to service failed";

fn run(input: &Bytes, gas_limit: u64, env: &Env) -> PrecompileResult {
    if let Some(called_fn) = SERVICES_MANAGER_ABI.methods.get(&input[0..4]) {
        match called_fn.0.as_str() {
            "getService" => get_service(input, gas_limit, env),
            "callService" => call_service(input, gas_limit, env),
            _ => Err(PrecompileErrors::Error(PrecompileError::Other(
                INCORRECT_INPUTS.into(),
            ))),
        }
    } else {
        Err(PrecompileErrors::Error(PrecompileError::Other(
            INCORRECT_INPUTS.into(),
        )))
    }
}

fn get_service(input: &Bytes, gas_limit: u64, env: &Env) -> PrecompileResult {
    let gas_used = 10000 as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas.into());
    }

    let mut handle_bytes: Vec<u8> = input.to_vec();
    handle_bytes.extend_from_slice(env.msg.caller.0.as_slice());
    let handle_hash = sha2::Sha256::digest(handle_bytes).to_vec();
    let contract_handle = H256::from_slice(&handle_hash);

    if GLOBAL_SM
        .lock()
        .unwrap()
        .service_handles
        .contains_key(&contract_handle)
    {
        return Ok(PrecompileOutput::new(
            gas_used,
            encode(&[
                Token::Uint(ethers::types::U256::from(contract_handle.0)),
                Token::String(String::new()),
            ])
            .into(),
        ));
    }

    // TODO: configure elsewhere
    let instantiate_resp_raw = send_to_requests_manager(input, "http://127.0.0.1:5605/");
    if let Err(_e) = instantiate_resp_raw {
        return Err(PrecompileErrors::Error(PrecompileError::Other(
            INSTANTIATE_FAILED.into(),
        )));
    };

    let instantiate_resp = instantiate_resp_raw.unwrap();
    let (service_handle, err): (H256, reth_primitives::bytes::Bytes) = SERVICES_MANAGER_ABI
        .decode_output("getService", &instantiate_resp)
        .map_err(|_e| PrecompileErrors::Error(PrecompileError::Other(INSTANTIATE_FAILED.into())))?;
    if err.len() != 0 {
        return Ok(PrecompileOutput::new(gas_used, instantiate_resp.into()));
    }

    GLOBAL_SM
        .lock()
        .unwrap()
        .service_handles
        .insert(contract_handle, (env.msg.caller, service_handle));

    Ok(PrecompileOutput::new(
        gas_used,
        encode(&[
            Token::Uint(ethers::types::U256::from(contract_handle.0)),
            Token::String(String::new()),
        ])
        .into(),
    ))
}

fn call_service(input: &Bytes, gas_limit: u64, env: &Env) -> PrecompileResult {
    let gas_used = 10000 as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas.into());
    }

    let (contract_handle, service_calldata): (H256, AbiBytes) = SERVICES_MANAGER_ABI
        .decode_input(input)
        .map_err(|_e| PrecompileErrors::Error(PrecompileError::Other(INCORRECT_INPUTS.into())))?;

    let locked_sm = GLOBAL_SM.lock().unwrap();
    let service_handle = match locked_sm.service_handles.get(&contract_handle) {
        None => Err(PrecompileErrors::Error(PrecompileError::Other(
            SERIVCE_MISCONFIGURED.into(),
        ))),
        Some(sh) => {
            if !sh.0.const_eq(&env.msg.caller) {
                // TODO
                // return Err(SERIVCE_MISCONFIGURED);
            }
            Ok(sh.1)
        }
    }?;

    // We could also overwrite the input to save on copying
    let remapped_calldata = SERVICES_MANAGER_ABI
        .encode(
            "callServiceWithContext",
            (
                Token::Tuple(vec![
                    Token::Uint(env.block.number.into()),
                    Token::Address(Address::from_slice(env.tx.caller.as_slice())),
                    Token::Address(Address::from_slice(env.msg.caller.as_slice())),
                ]),
                Token::FixedBytes(service_handle.0.into()),
                Token::Bytes(service_calldata),
            ),
        )
        .map_err(|_e| PrecompileErrors::Error(PrecompileError::Other(INCORRECT_INPUTS.into())))?;

    match send_to_requests_manager(&remapped_calldata.0, "http://127.0.0.1:5605/") {
        Err(_e) => PrecompileResult::Err(PrecompileErrors::Error(PrecompileError::Other(
            SERIVCE_REQUEST_FAILED.into(),
        ))),
        Ok(r) => PrecompileResult::Ok(PrecompileOutput::new(gas_used, r.into())),
    }
}

fn send_to_requests_manager(
    input: &reth_primitives::bytes::Bytes,
    path: &str,
) -> reqwest::Result<Vec<u8>> {
    let client = ReqwestClient::new();
    // TODO: configure elsewhere
    let res = client.post(path).body::<Vec<u8>>(input.to_vec()).send()?;

    let resp_bytes = res.bytes()?;
    Ok(resp_bytes.into())
}
