pub mod remote_db;
pub use crate::remote_db::RemoteDB;

use tokio::sync::{mpsc, watch};
use tokio::task::spawn_blocking;

use execution::rpc::http_rpc::HttpRpc;
use execution::state::State;
use execution::ExecutionClient;
use helios::types::{Block, Transactions};

use revm::db::{CacheDB, Database, EmptyDB};

use ethers::core::types::{Block as EthersBlock, BlockNumber, Bytes, TxHash};
use ethers::providers::{Http, Provider};
use ethers::utils;
use std::convert::TryFrom;

use revm::primitives::address;

#[tokio::main]
async fn main() {
    // Sanity check
    /* Fetch the latest block */
    let provider = Provider::<Http>::try_from("http://127.0.0.1:8545")
        .expect("could not instantiate HTTP Provider");

    let include_txs = utils::serialize(&false);
    let num = utils::serialize(&BlockNumber::Latest);

    let block: EthersBlock<TxHash> = provider
        .request("eth_getBlockByNumber", [num, include_txs])
        .await
        .unwrap();

    let helios_block = Block {
        number: block.number.unwrap(),
        base_fee_per_gas: block.base_fee_per_gas.unwrap(),
        difficulty: block.difficulty,
        extra_data: block.extra_data,
        gas_limit: block.gas_limit.as_u64().into(),
        gas_used: block.gas_used.as_u64().into(),
        hash: block.hash.unwrap(),
        logs_bloom: Bytes::from_iter(block.logs_bloom.unwrap().as_bytes().into_iter()),
        miner: block.author.unwrap_or_default(),
        mix_hash: block.mix_hash.unwrap(),
        nonce: String::from(""), // block.seal_fields
        parent_hash: block.parent_hash,
        receipts_root: block.receipts_root,
        sha3_uncles: block.uncles_hash,
        size: block.size.unwrap_or_default().as_u64().into(),
        state_root: block.state_root,
        timestamp: block.timestamp.as_u64().into(),
        total_difficulty: block.total_difficulty.unwrap_or_default().as_u64().into(),
        transactions: Transactions::Hashes(block.transactions),
        transactions_root: block.transactions_root,
        uncles: block.uncles,
    };

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
            .basic(address!("c01212a76b7927a02c445ca83b2a520049c465e4"))
            .unwrap()
            .unwrap()
            .balance;
        println!("balance: {}", balance);
    })
    .await
    .unwrap();
}
