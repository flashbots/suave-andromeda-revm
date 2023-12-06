pub mod remote_db;
pub use crate::remote_db::RemoteDB;

use tokio::sync::{mpsc, watch};
use tokio::task::spawn_blocking;

use execution::rpc::http_rpc::HttpRpc;
use execution::state::State;
use execution::ExecutionClient;

use revm::db::{CacheDB, Database, EmptyDB};

use ethers::core::types::{Block as EthersBlock, BlockNumber, TxHash};
use ethers::providers::{Http, Provider};
use ethers::utils as ethers_utils;
use std::convert::TryFrom;

use revm::primitives::address;

pub mod utils;
use crate::utils::ethers_block_to_helios;

#[tokio::main]
async fn main() {
    // Sanity check
    /* Fetch the latest block */
    let provider = Provider::<Http>::try_from("http://127.0.0.1:8545")
        .expect("could not instantiate HTTP Provider");

    let include_txs = ethers_utils::serialize(&false);
    let num = ethers_utils::serialize(&BlockNumber::Latest);

    let block: EthersBlock<TxHash> = provider
        .request("eth_getBlockByNumber", [num, include_txs])
        .await
        .unwrap();

    let helios_block = ethers_block_to_helios(block).expect("block malformed");

    let (_block_tx, block_rx) = mpsc::channel(1);
    let (finalized_block_tx, finalized_block_rx) = watch::channel(None);
    let rpc_state_provider: ExecutionClient<HttpRpc> = ExecutionClient::new(
        "http://127.0.0.1:8545",
        State::new(block_rx, finalized_block_rx, 1),
    )
    .unwrap();

    let mut remote_db = RemoteDB::new(rpc_state_provider, CacheDB::new(EmptyDB::new()));
    finalized_block_tx.send(Some(helios_block)).unwrap();

    spawn_blocking(move || {
        let balance = remote_db
            .basic(address!("164fd8d545fb0a1b803c23520b35043df1435e0b"))
            .unwrap()
            .unwrap()
            .balance;
        println!("balance: {}", balance);
    })
    .await
    .unwrap();
}
