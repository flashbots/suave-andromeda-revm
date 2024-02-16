use ethers;
use ethers::abi::{encode, Contract, Detokenize, Token};
use ethers::contract::{BaseContract, Lazy};

pub static BUILDER_ABI: Lazy<BaseContract> = Lazy::new(|| {
    let contract: Contract =
        serde_json::from_str(include_str!("../../out/Builder.sol/Builder.abi.json")).unwrap();
    BaseContract::from(contract)
});

pub fn builder_contract() -> BaseContract {
    BUILDER_ABI.clone()
}

#[derive(Debug)]
pub enum BuilderError {
    Error(String),
    InstantiationError(String),
    StreamError(String),
    InvalidCall,
    InvalidCalldata,
}

pub struct BuilderService {
    pub builder_abi: BaseContract,
    simulate_fn_abi: ethers::abi::Function,
    build_block_fn_abi: ethers::abi::Function,
}

impl BuilderService {
    pub fn new() -> Self {
        BuilderService {
            builder_abi: BUILDER_ABI.clone(),
            simulate_fn_abi: BUILDER_ABI.abi().function("simulate").unwrap().clone(),
            build_block_fn_abi: BUILDER_ABI.abi().function("buildBlock").unwrap().clone(),
        }
    }

    pub fn simulate(&self, inputs: &[u8]) -> Result<ethers::abi::Bytes, BuilderError> {
        let (_height, _signed_txs, profit): (
            ethers::abi::Uint,
            ethers::abi::Bytes,
            ethers::abi::Uint,
        ) = Detokenize::from_tokens(
            self.simulate_fn_abi
                .decode_input(inputs)
                .map_err(|e| BuilderError::Error(e.to_string()))?,
        )
        .map_err(|_e| BuilderError::Error(_e.to_string()))?;

        Ok(encode(&[Token::Tuple(vec![Token::Uint(profit)])]))
    }

    pub fn build_block(&mut self, inputs: &[u8]) -> Result<ethers::abi::Bytes, BuilderError> {
        let bundles: Vec<(ethers::abi::Uint, ethers::abi::Bytes, ethers::abi::Uint)> =
            Detokenize::from_tokens(
                self.build_block_fn_abi
                    .decode_input(inputs)
                    .map_err(|_e| BuilderError::InvalidCalldata)?,
            )
            .map_err(|_e| BuilderError::InvalidCalldata)?;

        Ok(encode(&[Token::Uint(ethers::abi::Uint::from(
            bundles.len(),
        ))]))
    }
}
