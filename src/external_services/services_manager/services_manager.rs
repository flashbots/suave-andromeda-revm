use ethers::abi::Detokenize;
use sha2::*;
use std::collections::HashMap;

use ethers;
use ethers::abi::{Contract, Token};
use ethers::contract::{BaseContract, Lazy};
use ethers::types::{Bytes, H256};

use crate::builder::{BuilderError, BuilderService};
use crate::external_services::common::CallContext;
use crate::pubsub::{RedisPubsub, RedisPubsubError};
use crate::redis::{RedisService, RedisServiceError};

pub static SERVICES_MANAGER_ABI: Lazy<BaseContract> = Lazy::new(|| {
    let contract: Contract =
        serde_json::from_str(include_str!("../../../out/ServicesManager.sol/SM.abi.json")).unwrap();
    BaseContract::from(contract)
});

pub fn service_manager_contract() -> BaseContract {
    SERVICES_MANAGER_ABI.clone()
}

pub struct ServicesManager {
    pub _sm_contract: BaseContract,
    get_service_fn_abi: ethers::abi::Function,
    call_service_fn_abi: ethers::abi::Function,
    service_handles: HashMap<H256, Box<dyn Service>>,
}

impl ServicesManager {
    pub fn new() -> Self {
        let sm_abi = SERVICES_MANAGER_ABI.abi();
        ServicesManager {
            _sm_contract: service_manager_contract(),
            get_service_fn_abi: sm_abi.function("getService").unwrap().clone(),
            call_service_fn_abi: sm_abi.function("callServiceWithContext").unwrap().clone(),
            service_handles: HashMap::new(),
        }
    }

    pub fn run(&mut self, inputs: &[u8]) -> Result<ethers::abi::Bytes, ServiceError> {
        if inputs.len() < 4 {
            return Err(ServiceError::InvalidCalldata);
        }
        if let Some(called_fn) = SERVICES_MANAGER_ABI.methods.get(&inputs[0..4]) {
            match called_fn.0.as_str() {
                "getService" => self.get_service(&inputs[4..]),
                "callServiceWithContext" => self.call_service(&inputs[4..]),
                _ => Err(ServiceError::InvalidCall),
            }
        } else {
            Err(ServiceError::InvalidCall)
        }
    }

    fn get_service(&mut self, inputs: &[u8]) -> Result<ethers::abi::Bytes, ServiceError> {
        let (service_name, config): (String, Bytes) = Detokenize::from_tokens(
            self.get_service_fn_abi
                .decode_input(inputs)
                .map_err(|_e| ServiceError::InvalidCalldata)?,
        )
        .map_err(|_e| ServiceError::InvalidCalldata)?;

        let sha2_hash = sha2::Sha256::digest(&config).to_vec();
        let config_hash = H256::from_slice(&sha2_hash);

        if let Some(_s) = self.service_handles.get(&config_hash) {
            return Ok(ethers::abi::encode(&[
                Token::FixedBytes(config_hash.0.into()),
                Token::String(String::from("")),
            ]));
        }

        // TODO: define elsewhere
        let service: Box<dyn Service> = match service_name.as_str() {
            "redis" => Ok(Box::new(RedisService::new()) as Box<dyn Service>),
            "pubsub" => Ok(Box::new(RedisPubsub::new()) as Box<dyn Service>),
            "builder" => Ok(Box::new(BuilderService::new()) as Box<dyn Service>),
            _ => Err(ServiceError::InvalidCall),
        }?;

        service.instantiate(config)?;

        self.service_handles.insert(config_hash, service);
        Ok(ethers::abi::encode(&[
            Token::FixedBytes(config_hash.0.into()),
            Token::String(String::from("")),
        ]))
    }

    fn call_service(&mut self, inputs: &[u8]) -> Result<ethers::abi::Bytes, ServiceError> {
        let (context, handle, cdata): (CallContext, H256, Bytes) = Detokenize::from_tokens(
            self.call_service_fn_abi
                .decode_input(inputs)
                .map_err(|_e| ServiceError::InvalidCalldata)?,
        )
        .map_err(|_e| ServiceError::InvalidCalldata)?;

        let mut selector: [u8; 4] = [0; 4];
        selector.copy_from_slice(&cdata[0..4]);

        println!("-> selector: {:?}", &selector);

        match self.service_handles.get_mut(&handle) {
            None => Err(ServiceError::ServiceNotInitialized),
            Some(service) => service.call(selector, context, &cdata[4..]),
        }
    }
}

#[derive(Debug)]
pub enum ServiceError {
    RedisServiceError(RedisServiceError),
    RedisPubsubError(RedisPubsubError),
    BuilderError(BuilderError),

    InstantiationError(String),
    InvalidCall,
    InvalidCalldata,
    ServiceNotInitialized,
}

pub trait Service {
    fn instantiate(&self, config: Bytes) -> Result<(), ServiceError>;
    fn call(
        &mut self,
        selector: [u8; 4],
        context: CallContext,
        inputs: &[u8],
    ) -> Result<ethers::abi::Bytes, ServiceError>;
}

impl Service for RedisService {
    fn instantiate(&self, config: Bytes) -> Result<(), ServiceError> {
        if config.len() != 0 {
            return Err(ServiceError::InstantiationError(String::from(
                "unexpected config passed",
            )));
        }
        Ok(())
    }

    fn call(
        &mut self,
        selector: [u8; 4],
        context: CallContext,
        inputs: &[u8],
    ) -> Result<ethers::abi::Bytes, ServiceError> {
        if let Some(called_fn) = self.redis_abi.methods.get(&selector) {
            println!("{}", called_fn.0.as_str());
            match called_fn.0.as_str() {
                "get" => self.get(context, inputs),
                "set" => self.set(context, inputs),
                _ => Err(RedisServiceError::InvalidCall),
            }
            .map_err(|e| ServiceError::RedisServiceError(e))
        } else {
            Err(ServiceError::InvalidCall)
        }
    }
}

impl Service for RedisPubsub {
    fn instantiate(&self, config: Bytes) -> Result<(), ServiceError> {
        if config.len() != 0 {
            return Err(ServiceError::InstantiationError(String::from(
                "unexpected config passed",
            )));
        }
        Ok(())
    }

    fn call(
        &mut self,
        selector: [u8; 4],
        context: CallContext,
        inputs: &[u8],
    ) -> Result<ethers::abi::Bytes, ServiceError> {
        if let Some(called_fn) = self.pubsub_abi.methods.get(&selector) {
            match called_fn.0.as_str() {
                "publish" => self.publish(context, inputs),
                "subscribe" => self.subscribe(context, inputs),
                "get_message" => self.get_message(context, inputs),
                "unsubscribe" => self.unsubscribe(context, inputs),
                _ => Err(RedisPubsubError::InvalidCall),
            }
            .map_err(|e| ServiceError::RedisPubsubError(e))
        } else {
            Err(ServiceError::InvalidCall)
        }
    }
}

impl Service for BuilderService {
    fn instantiate(&self, config: Bytes) -> Result<(), ServiceError> {
        if config.len() == 0 {
            return Err(ServiceError::InstantiationError(String::from(
                "missing config",
            )));
        }
        Ok(())
    }

    fn call(
        &mut self,
        selector: [u8; 4],
        _context: CallContext,
        inputs: &[u8],
    ) -> Result<ethers::abi::Bytes, ServiceError> {
        if let Some(called_fn) = self.builder_abi.methods.get(&selector) {
            match called_fn.0.as_str() {
                "simulate" => self.simulate(inputs),
                "buildBlock" => self.build_block(inputs),
                _ => Err(BuilderError::InvalidCall),
            }
            .map_err(|e| ServiceError::BuilderError(e))
        } else {
            Err(ServiceError::InvalidCall)
        }
    }
}
