use std::collections::HashMap;

use ethers::abi::{encode, Contract, Detokenize, Token};
use ethers::contract::{BaseContract, Lazy};
use ethers::types::Bytes;

use crate::external_services::common::CallContext;

pub static REDIS_ABI: Lazy<BaseContract> = Lazy::new(|| {
    let contract: Contract =
        serde_json::from_str(include_str!("../../out/Redis.sol/Redis.abi.json")).unwrap();
    BaseContract::from(contract)
});

pub fn redis_contract() -> BaseContract {
    REDIS_ABI.clone()
}

#[derive(Debug)]
pub enum RedisServiceError {
    Error(String),
    InstantiationError(String),
    StreamError(String),
    InvalidCall,
    InvalidCalldata,
    ConnectionFailure,
}

use redis;

pub struct RedisService {
    _client: redis::Client,
    pub redis_abi: BaseContract,

    temp_values: HashMap<String, Bytes>,

    get_fn_abi: ethers::abi::Function,
    set_fn_abi: ethers::abi::Function,
}

impl RedisService {
    pub fn new(endpoint: String) -> Self {
        let redis_contract = REDIS_ABI.clone();
        let redis_abi = redis_contract.abi();

        let client = redis::Client::open(endpoint).unwrap();

        RedisService {
            _client: client,
            redis_abi: redis_contract.to_owned(),
            temp_values: HashMap::new(),
            get_fn_abi: redis_abi.function("get").unwrap().clone(),
            set_fn_abi: redis_abi.function("set").unwrap().clone(),
        }
    }

    pub fn get(
        &self,
        context: CallContext,
        inputs: &[u8],
    ) -> Result<ethers::abi::Bytes, RedisServiceError> {
        let mut key: String = Detokenize::from_tokens(
            self.get_fn_abi
                .decode_input(inputs)
                .map_err(|_e| RedisServiceError::InvalidCalldata)?,
        )
        .map_err(|_e| RedisServiceError::InvalidCalldata)?;

        let caller = context.1.to_string();
        if !key.starts_with(&caller) {
            key = caller + &key;
        }

        if let Some(value) = self.temp_values.get(&key) {
            return Ok(encode(&[Token::Bytes(value.to_owned().0.into())]));
        }

        Ok(encode(&[Token::Bytes(vec![])]))
    }

    pub fn set(
        &mut self,
        context: CallContext,
        inputs: &[u8],
    ) -> Result<ethers::abi::Bytes, RedisServiceError> {
        let (mut key, value): (String, Bytes) = Detokenize::from_tokens(
            self.set_fn_abi
                .decode_input(inputs)
                .map_err(|_e| RedisServiceError::InvalidCalldata)?,
        )
        .map_err(|_e| RedisServiceError::InvalidCalldata)?;

        let caller = context.1.to_string();
        if !key.starts_with(&caller) {
            key = caller + &key;
        }

        self.temp_values.insert(key, value);
        Ok(vec![])
    }
}
