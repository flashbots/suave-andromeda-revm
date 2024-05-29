use ethers::abi::{encode, Contract, Detokenize, Token};
use ethers::contract::{BaseContract, Lazy};
use ethers::types::Bytes;

use crate::external_services::common::CallContext;

pub static RPC_ABI: Lazy<BaseContract> = Lazy::new(|| {
    let contract: Contract =
        serde_json::from_str(include_str!("../../out/RPC.sol/BlockchainRPC.abi.json")).unwrap();
    BaseContract::from(contract)
});

pub fn rpc_contract() -> BaseContract {
    RPC_ABI.clone()
}

#[derive(Debug)]
pub enum RPCServiceError {
    Error(String),
    InstantiationError(String),
    StreamError(String),
    InvalidCall,
    InvalidCalldata,
    ConnectionFailure,
}

pub struct RPCService {
    pub abi: BaseContract,

    chain_endpoints: Vec<(U256, String)>,

    eth_call_fn_abi: ethers::abi::Function,
}

impl RPCService {
    pub fn new(chain_endpoints: Vec<(U256, String)>) -> Self {
        let rpc_abi = rpc_contract.abi();

        RedisService {
            abi: rpc_contract(),
            chain_endpoints,
            eth_call_fn_abi: rpc_abi.function("eth_call").unwrap().clone(),
        }
    }

    pub fn eth_call(
        &mut self,
        context: CallContext,
        inputs: &[u8],
    ) -> Result<ethers::abi::Bytes, RedisServiceError> {
        let (method, params): (String, Vec<Bytes>) = Detokenize::from_tokens(
            self.eth_call_fn_abi
                .decode_input(inputs)
                .map_err(|_e| RPCServiceError::InvalidCalldata)?,
        )
        .map_err(|_e| RPCServiceError::InvalidCalldata)?;

        let res: Result<Vec<u8>, _> = self.client.get(&key);
        match res {
            Ok(value) => Ok(encode(&[Token::Bytes(value)])),
            Err(e) => {
                dbg!("redis: could not get {}: {}", &key, e);
                Ok(encode(&[Token::Bytes(vec![])]))
            }
        }
    }
}
