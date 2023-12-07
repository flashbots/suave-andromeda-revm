pub use crate::remote_db::{RemoteDB, RemoteDBError};

use core::convert::Infallible;

use tokio::sync::{mpsc, watch};

use execution::rpc::http_rpc::HttpRpc;
use execution::state::State;
use execution::ExecutionClient;
use helios::prelude::Block;

use revm::db::{CacheDB, EmptyDB};

use ethers::core::types::{Block as EthersBlock, BlockNumber, TxHash};
use ethers::providers::{Http, Provider, ProviderError};
use ethers::utils as ethers_utils;
use std::convert::TryFrom;

use crate::utils::{ethers_block_to_helios, BlockError};
use helios::types::BlockTag;

use revm::{
    primitives::{EVMError, ExecutionResult, TxEnv},
    EVM,
};

pub struct StatefulExecutor {
    pub rpc_state_provider: ExecutionClient<HttpRpc>,
    pub http_provider: Provider<Http>,
    finalized_block_tx: watch::Sender<Option<Block>>,
}

#[derive(Debug)]
pub enum StatefulExecutorError {
    BlockError(BlockError),
    ProviderError(ProviderError),
    EVMError(EVMError<RemoteDBError<Infallible>>),
}

impl StatefulExecutor {
    pub fn new_with_rpc(rpc: String) -> Self {
        let (_block_tx, block_rx) = mpsc::channel(1);
        let (finalized_block_tx, finalized_block_rx) = watch::channel(None);
        let rpc_state_provider: ExecutionClient<HttpRpc> =
            ExecutionClient::new(&rpc, State::new(block_rx, finalized_block_rx, 1))
                .expect("could not instantiate execution client");

        let http_provider =
            Provider::<Http>::try_from(rpc.clone()).expect("could not instantiate HTTP Provider");

        StatefulExecutor {
            rpc_state_provider,
            http_provider,
            finalized_block_tx,
        }
    }

    pub async fn advance(&self, block_tag: BlockTag) -> Result<(), StatefulExecutorError> {
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
        self.finalized_block_tx
            .send(Some(helios_block))
            .expect("could not submit new block to state");
        Ok(())
    }

    pub fn execute(&self, tx: TxEnv) -> Result<ExecutionResult, StatefulExecutorError> {
        let mut evm = EVM::new();
        evm.database(RemoteDB::new(
            self.rpc_state_provider.clone(),
            CacheDB::new(EmptyDB::new()),
        ));
        evm.env.tx = tx;
        match evm.transact() {
            Ok(evm_res) => Ok(evm_res.result),
            Err(err) => Err(StatefulExecutorError::EVMError(err)),
        }
    }
}
