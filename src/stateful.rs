pub use crate::remote_db::{RemoteDB, RemoteDBError};

use core::convert::Infallible;

use std::io;

use tokio::runtime::Handle;
use tokio::sync::{mpsc, watch};
use tokio::task::block_in_place;

use execution::rpc::http_rpc::HttpRpc;
use execution::state::State;
use execution::ExecutionClient;
use helios::prelude::Block;

use revm::{
    db::{CacheDB, EmptyDB},
    inspectors::TracerEip3155,
    primitives::SpecId,
    primitives::{Address, B256, U256},
    primitives::{BlockEnv, CfgEnv, EVMError, Env, ExecutionResult, MsgEnv, TxEnv},
    Transact,
};

use ethers::core::types::{Block as EthersBlock, BlockNumber, TxHash};
use ethers::providers::{Http, Provider, ProviderError};
use ethers::utils as ethers_utils;
use std::convert::TryFrom;

use crate::consensus::Consensus;
use crate::utils::{ethers_block_to_helios, BlockError};
use eyre::Report;
use helios::types::BlockTag;

pub struct StatefulExecutor {
    pub rpc_state_provider: ExecutionClient<HttpRpc>,
    pub http_provider: Provider<Http>,
    pub consensus: Consensus,
    finalized_block_tx: watch::Sender<Option<Block>>,
}

use crate::new_andromeda_revm;

#[derive(Debug)]
pub enum StatefulExecutorError {
    BlockError(BlockError),
    RPCError(Report),
    ProviderError(ProviderError),
    EVMError(EVMError<RemoteDBError<Infallible>>),
    ConsensusError(consensus::errors::ConsensusError),
}

impl StatefulExecutor {
    pub fn new_with_rpc(rpc: String) -> Self {
        let (_block_tx, block_rx) = mpsc::channel(1);
        let (finalized_block_tx, finalized_block_rx) = watch::channel(None);
        let consensus = Consensus::new().unwrap();
        let rpc_state_provider: ExecutionClient<HttpRpc> =
            ExecutionClient::new(&rpc, State::new(block_rx, finalized_block_rx, 1))
                .expect("could not instantiate execution client");

        let http_provider =
            Provider::<Http>::try_from(rpc.clone()).expect("could not instantiate HTTP Provider");

        StatefulExecutor {
            rpc_state_provider,
            consensus,
            http_provider,
            finalized_block_tx,
        }
    }

    pub async fn advance(&mut self, block_tag: BlockTag) -> Result<(), StatefulExecutorError> {
        let block_selector = match block_tag {
            BlockTag::Latest => ethers_utils::serialize(&BlockNumber::Latest),
            BlockTag::Finalized => ethers_utils::serialize(&BlockNumber::Finalized),
            BlockTag::Number(n) => ethers_utils::serialize(&BlockNumber::Number(n.into())),
        };

        let block: EthersBlock<TxHash> = self
            .http_provider
            .request(
                "eth_getBlockByNumber",
                [block_selector, ethers_utils::serialize(&false)],
            )
            .await
            .map_err(|err| StatefulExecutorError::ProviderError(err))?;

        let helios_block =
            ethers_block_to_helios(block).map_err(|err| StatefulExecutorError::BlockError(err))?;

        self.consensus
            .advance(&helios_block)
            .map_err(|err| StatefulExecutorError::ConsensusError(err))?;

        self.finalized_block_tx
            .send(Some(helios_block))
            .expect("could not submit new block to state");
        Ok(())
    }

    pub fn execute(
        &self,
        tx: TxEnv,
        trace: bool,
    ) -> Result<ExecutionResult, StatefulExecutorError> {
        let block_env = match block_in_place(|| {
            Handle::current().block_on(self.rpc_state_provider.get_block(BlockTag::Latest, false))
        }) {
            Err(err) => Err(StatefulExecutorError::RPCError(err)),
            Ok(b) => Ok(BlockEnv {
                number: U256::from(b.number.as_u64()),
                coinbase: Address::from_slice(b.miner.as_bytes()),
                timestamp: U256::from(b.timestamp.as_u64()),
                gas_limit: U256::from(b.gas_limit.as_u64()),
                basefee: U256::from_limbs(b.base_fee_per_gas.0),
                difficulty: U256::from_limbs(b.difficulty.0),
                prevrandao: Some(B256::ZERO), // TODO! REVM thinks this is post-merge
                blob_excess_gas_and_price: None,
            }),
        }?;

        let mut cfg = CfgEnv::default();
        cfg.spec_id = SpecId::SHANGHAI;

        let msg = MsgEnv {
            caller: tx.caller.clone(),
        };

        let mut env = Env {
            cfg,
            msg,
            tx,
            block: block_env,
        };

        let mut db = RemoteDB::new(
            self.rpc_state_provider.clone(),
            CacheDB::new(EmptyDB::new()),
        );

        match match trace {
            true => {
                let writer = Box::new(io::stderr());
                let mut inspector = TracerEip3155::new(writer, true, true);
                let mut evm_impl = new_andromeda_revm(&mut db, &mut env, Some(&mut inspector));
                evm_impl.transact()
            }
            false => {
                let mut evm_impl = new_andromeda_revm(&mut db, &mut env, None);
                evm_impl.transact()
            }
        } {
            Ok(evm_res) => Ok(evm_res.result),
            Err(err) => Err(StatefulExecutorError::EVMError(err)),
        }
    }
}

#[derive(Debug)]
pub enum CommandError {
    InputError(String),
    SerializationError(String),
    StatefulExecutorError(StatefulExecutorError),
}

impl StatefulExecutor {
    pub async fn execute_command(
        &mut self,
        input: &str,
        trace: bool,
    ) -> Result<String, CommandError> {
        // We support two commands: advance <block number|latest|empty(latest)> and execute <TxEnv json>
        let (command, args) = match input.split_once(' ') {
            Some((command, args)) => (command, Some(args)),
            None => (input, None),
        };

        match command {
            "advance" => {
                let tag = match args {
                    None => Ok(BlockTag::Latest),
                    Some("latest") => Ok(BlockTag::Latest),
                    Some(args) => match args.parse::<u64>() {
                        Ok(n) => Ok(BlockTag::Number(n)),
                        _ => Err(CommandError::InputError(String::from("invalid block tag"))),
                    },
                }?;

                match self.advance(tag).await {
                    Ok(_) => Ok(String::from("advanced")),
                    Err(e) => Err(CommandError::StatefulExecutorError(e)),
                }
            }
            "execute" => match args {
                None => Err(CommandError::InputError(String::from(
                    "no args passed to execute",
                ))),
                Some(args) => {
                    let tx = match serde_json::from_str::<TxEnv>(args) {
                        Ok(tx) => Ok(tx),
                        Err(e) => Err(CommandError::SerializationError(format!(
                            "could not parse tx: {}",
                            e
                        ))),
                    }?;

                    match self.execute(tx, trace) {
                        Ok(res) => match serde_json::to_string(&res) {
                            Ok(res) => Ok(String::from(res)),
                            Err(e) => Err(CommandError::InputError(format!(
                                "could not serialize result: {}",
                                e
                            ))),
                        },
                        Err(e) => Err(CommandError::InputError(format!(
                            "could not execute: {:?}",
                            e
                        ))),
                    }
                }
            },
            _ => Err(CommandError::InputError(format!("invalid command"))),
        }
    }
}
