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
        serde_json::from_str(include_str!("../../out/ServicesManager.sol/SM.abi.json")).unwrap();
    BaseContract::from(contract)
});

pub fn service_manager_contract() -> BaseContract {
    SERVICES_MANAGER_ABI.clone()
}

pub struct ServicesManager {
    config: Config,
    pub _sm_contract: BaseContract,
    get_service_fn_abi: ethers::abi::Function,
    call_service_fn_abi: ethers::abi::Function,
    service_handles: HashMap<H256, Box<dyn Service>>,
}

#[derive(Clone)]
pub struct Config {
    pub kv_redis_endpoint: String,
    pub pubsub_redis_endpoint: String,
}

impl ServicesManager {
    pub fn new(config: Config) -> Self {
        let sm_abi = SERVICES_MANAGER_ABI.abi();
        ServicesManager {
            config,
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

        let sha2_hash = sha2::Sha256::digest(inputs).to_vec();
        let config_hash = H256::from_slice(&sha2_hash);

        if let Some(_s) = self.service_handles.get(&config_hash) {
            return Ok(ethers::abi::encode(&[
                Token::FixedBytes(config_hash.0.into()),
                Token::String(String::from("")),
            ]));
        }

        // TODO: define elsewhere
        let service: Box<dyn Service> = match service_name.as_str() {
            "redis" => Ok(
                Box::new(RedisService::new(self.config.kv_redis_endpoint.clone()))
                    as Box<dyn Service>,
            ),
            "pubsub" => Ok(
                Box::new(RedisPubsub::new(self.config.pubsub_redis_endpoint.clone()))
                    as Box<dyn Service>,
            ),
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

        match self.service_handles.get_mut(&handle) {
            None => Err(ServiceError::ServiceNotInitialized),
            Some(service) => match service.function_name_from_selector(&selector) {
                Some(fn_name) => {
                    let ret = service.call(fn_name.as_str(), context, &cdata[4..]);
                    println!("call {}::{} -> {:?}", service.name(), &fn_name, ret);
                    return ret;
                }
                None => {
                    println!(
                        "invalid {} call with selector {:?}",
                        service.name(),
                        selector.as_slice()
                    );
                    Err(ServiceError::InvalidCall)
                }
            },
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
    fn name(&self) -> String;
    fn function_name_from_selector(&self, selector: &[u8; 4]) -> Option<String>;
    fn instantiate(&self, config: Bytes) -> Result<(), ServiceError>;
    fn call(
        &mut self,
        fn_name: &str,
        context: CallContext,
        inputs: &[u8],
    ) -> Result<ethers::abi::Bytes, ServiceError>;
}

impl Service for RedisService {
    fn name(&self) -> String {
        String::from("redis")
    }

    fn function_name_from_selector(&self, selector: &[u8; 4]) -> Option<String> {
        match self.redis_abi.methods.get(selector) {
            Some((fn_name, _)) => Some(fn_name.clone()),
            None => None,
        }
    }

    fn instantiate(&self, config: Bytes) -> Result<(), ServiceError> {
        if config.len() != 0 {
            return Err(ServiceError::InstantiationError(String::from(
                "unexpected config passed",
            )));
        }

        println!("instantiated redis with {:?}", self.redis_abi.methods);

        Ok(())
    }

    fn call(
        &mut self,
        fn_name: &str,
        context: CallContext,
        inputs: &[u8],
    ) -> Result<ethers::abi::Bytes, ServiceError> {
        match fn_name {
            "get" => self.get(context, inputs),
            "set" => self.set(context, inputs),
            _ => Err(RedisServiceError::InvalidCall),
        }
        .map_err(|e| ServiceError::RedisServiceError(e))
    }
}

impl Service for RedisPubsub {
    fn name(&self) -> String {
        String::from("pubsub")
    }

    fn function_name_from_selector(&self, selector: &[u8; 4]) -> Option<String> {
        match self.pubsub_abi.methods.get(selector) {
            Some((fn_name, _)) => Some(fn_name.clone()),
            None => None,
        }
    }

    fn instantiate(&self, config: Bytes) -> Result<(), ServiceError> {
        if config.len() != 0 {
            return Err(ServiceError::InstantiationError(String::from(
                "unexpected config passed",
            )));
        }

        println!("instantiated pubsub with {:?}", self.pubsub_abi.methods);

        Ok(())
    }

    fn call(
        &mut self,
        fn_name: &str,
        context: CallContext,
        inputs: &[u8],
    ) -> Result<ethers::abi::Bytes, ServiceError> {
        match fn_name {
            "publish" => self.publish(context, inputs),
            "subscribe" => self.subscribe(context, inputs),
            "get_message" => self.get_message(context, inputs),
            "unsubscribe" => self.unsubscribe(context, inputs),
            _ => Err(RedisPubsubError::InvalidCall),
        }
        .map_err(|e| ServiceError::RedisPubsubError(e))
    }
}

impl Service for BuilderService {
    fn name(&self) -> String {
        String::from("builder")
    }

    fn function_name_from_selector(&self, selector: &[u8; 4]) -> Option<String> {
        match self.builder_abi.methods.get(selector) {
            Some((fn_name, _)) => Some(fn_name.clone()),
            None => None,
        }
    }

    fn instantiate(&self, config: Bytes) -> Result<(), ServiceError> {
        if config.len() == 0 {
            return Err(ServiceError::InstantiationError(String::from(
                "missing config",
            )));
        }

        println!("instantiated builder with {:?}", self.builder_abi.methods);

        Ok(())
    }

    fn call(
        &mut self,
        fn_name: &str,
        _context: CallContext,
        inputs: &[u8],
    ) -> Result<ethers::abi::Bytes, ServiceError> {
        match fn_name {
            "simulate" => self.simulate(inputs),
            "buildBlock" => self.build_block(inputs),
            _ => Err(BuilderError::InvalidCall),
        }
        .map_err(|e| ServiceError::BuilderError(e))
    }
}
