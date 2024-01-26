use lazy_static::lazy_static;
use reqwest::blocking::Client as ReqwestClient;

use ethers::abi::{encode, AbiEncode, Bytes as AbiBytes, Token};
use ethers::types::{Address, Bytes, H256};

use revm::precompile::{
    EnvPrecompileFn, Precompile, PrecompileError, PrecompileResult, PrecompileWithAddress,
};
use revm::primitives::{Address as RevmAddress, Env};

use std::collections::HashMap;
use std::sync::Mutex;

use crate::u64_to_address;

use crate::services_manager::SERVICES_MANAGER_ABI;

pub const RUN: PrecompileWithAddress = PrecompileWithAddress::new(
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

const INSTANTIATE_FAILED: PrecompileError =
    PrecompileError::CustomPrecompileError("could not instantiate requested protocol");
const INCORRECT_INPUTS: PrecompileError =
    PrecompileError::CustomPrecompileError("incorrect inputs passed in");
const SERIVCE_MISCONFIGURED: PrecompileError =
    PrecompileError::CustomPrecompileError("service is misconfigured");
const SERIVCE_REQUEST_FAILED: PrecompileError =
    PrecompileError::CustomPrecompileError("request to service failed");

fn run(input: &[u8], gas_limit: u64, env: &Env) -> PrecompileResult {
    if let Some(called_fn) = SERVICES_MANAGER_ABI.methods.get(&input[0..4]) {
        match called_fn.0.as_str() {
            "getService" => get_service(input, gas_limit, env),
            "callService" => call_service(input, gas_limit, env),
            _ => Err(INCORRECT_INPUTS),
        }
        .map_err(|e| {
            println!("{:?}", e);
            e
        })
    } else {
        Err(INCORRECT_INPUTS)
    }
}

fn get_service(input: &[u8], gas_limit: u64, env: &Env) -> PrecompileResult {
    let gas_used = 10000 as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    // TODO: configure elsewhere
    let instantiate_resp_raw = send_to_requests_manager(input, "http://127.0.0.1:5605/");
    if let Err(e) = instantiate_resp_raw {
        println!("{:?}", e);
        return Err(INSTANTIATE_FAILED);
    };

    // Handle should really just be a salted hash of the (service_name, config)
    let instantiate_resp = instantiate_resp_raw.unwrap();
    let (service_handle, err): (H256, Bytes) = SERVICES_MANAGER_ABI
        .decode_output("getService", &instantiate_resp)
        .map_err(|_e| INSTANTIATE_FAILED)?;
    if err.len() != 0 {
        return Ok((gas_used, instantiate_resp));
    }

    let contract_handle = H256::random();

    // Only whoever knows the random handle can access the service
    // Should probably be done at the contract level using secure random
    GLOBAL_SM
        .lock()
        .unwrap()
        .service_handles
        .insert(contract_handle, (env.msg.caller, service_handle));

    let mut ret = service_handle.encode();
    ret.extend(ethers::abi::Bytes::new());
    Ok((
        gas_used,
        encode(&[
            Token::Uint(ethers::types::U256::from(contract_handle.0)),
            Token::String(String::new()),
        ]),
    ))
}

fn call_service(input: &[u8], gas_limit: u64, env: &Env) -> PrecompileResult {
    let gas_used = 10000 as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    let (contract_handle, service_calldata): (H256, AbiBytes) = SERVICES_MANAGER_ABI
        .decode_input(input)
        .map_err(|_e| INCORRECT_INPUTS)?;

    let locked_sm = GLOBAL_SM.lock().unwrap();
    let service_handle = match locked_sm.service_handles.get(&contract_handle) {
        None => Err(SERIVCE_MISCONFIGURED),
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
        .map_err(|_e| INCORRECT_INPUTS)?;

    match send_to_requests_manager(&remapped_calldata.0, "http://127.0.0.1:5605/") {
        Err(_e) => PrecompileResult::Err(SERIVCE_REQUEST_FAILED),
        Ok(r) => PrecompileResult::Ok((gas_used, r)),
    }
}

fn send_to_requests_manager(input: &[u8], path: &str) -> reqwest::Result<Vec<u8>> {
    let client = ReqwestClient::new();
    // TODO: configure elsewhere
    let res = client.post(path).body::<Vec<u8>>(input.into()).send()?;

    let resp_bytes = res.bytes()?;
    Ok(resp_bytes.into())
}
