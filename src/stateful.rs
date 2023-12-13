pub use crate::remote_db::{RemoteDB, RemoteDBError};

use core::convert::Infallible;

use std::io;

use tokio::sync::{mpsc, watch};

use execution::rpc::http_rpc::HttpRpc;
use execution::state::State;
use execution::ExecutionClient;
use helios::prelude::Block;

use revm::db::{CacheDB, EmptyDB};
use revm::inspectors::TracerEip3155;

use ethers::core::types::{Block as EthersBlock, BlockNumber, TxHash};
use ethers::providers::{Http, Provider, ProviderError};
use ethers::utils as ethers_utils;
use std::convert::TryFrom;

use crate::consensus::Consensus;
use crate::utils::{ethers_block_to_helios, BlockError};
use helios::types::BlockTag;

use revm::{
    primitives::{EVMError, ExecutionResult, TxEnv},
    EVM,
};

pub struct StatefulExecutor {
    pub rpc_state_provider: ExecutionClient<HttpRpc>,
    pub http_provider: Provider<Http>,
    pub consensus: Consensus,
    finalized_block_tx: watch::Sender<Option<Block>>,
}

#[derive(Debug)]
pub enum StatefulExecutorError {
    BlockError(BlockError),
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
        let mut evm = EVM::new();
        evm.env.tx = tx;
        evm.database(RemoteDB::new(
            self.rpc_state_provider.clone(),
            CacheDB::new(EmptyDB::new()),
        ));
        match match trace {
            false => evm.transact(),
            true => {
                let writer = Box::new(io::stderr());
                evm.inspect(TracerEip3155::new(writer, true, true))
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
