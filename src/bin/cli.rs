pub use suave_andromeda_revm::{ethers_block_to_helios, RemoteDB};

use serde_json;

use clap::Parser;

use tokio::sync::{mpsc, watch};
use tokio::task::spawn_blocking;

use execution::rpc::http_rpc::HttpRpc;
use execution::state::State;
use execution::ExecutionClient;

use revm::db::{CacheDB, Database, EmptyDB};

use ethers::core::types::BlockNumber;
use ethers::providers::{Http, Provider};
use std::convert::TryFrom;

use revm::{
    primitives::{EVMError, ExecutionResult, TxEnv},
    EVM,
};

use ethers::utils as ethers_utils;

use suave_andromeda_revm::precompiles::lib::{set_precompile_config, PrecompileConfig};

#[derive(Parser)]
struct Cli {
    /// The rpc endpoint to connect to
    #[arg(long, default_value_t = String::from("http://127.0.0.1:8545"))]
    rpc: String,
    #[arg(long, default_values_t = [String::from("*")], help = "Whitelist for http precompiles. Can be URL, '*', or contract address (caller)")]
    http_whitelist: Vec<String>,
    /// The transaction to execute (rlp? encoded)
    tx_bytes: String,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let tx: TxEnv =
        serde_json::from_str(args.tx_bytes.as_str()).expect("could not parse transaction");

    set_precompile_config(PrecompileConfig {
        http_whitelist: args.http_whitelist,
    });

    /* Fetch the latest block */
    /* Alternatively the block could be passed in via command line */
    let provider =
        Provider::<Http>::try_from(args.rpc.clone()).expect("could not instantiate HTTP Provider");

    let block = provider
        .request(
            "eth_getBlockByNumber",
            [
                ethers_utils::serialize(&false),
                ethers_utils::serialize(&BlockNumber::Latest),
            ],
        )
        .await
        .expect("could not fetch latest block");

    let (_block_tx, block_rx) = mpsc::channel(1);
    let (finalized_block_tx, finalized_block_rx) = watch::channel(None);
    let rpc_state_provider: ExecutionClient<HttpRpc> = ExecutionClient::new(
        &args.rpc.clone(),
        State::new(block_rx, finalized_block_rx, 1),
    )
    .unwrap();

    let mut remote_db = RemoteDB::new(rpc_state_provider, CacheDB::new(EmptyDB::new()));
    finalized_block_tx
        .send(Some(
            ethers_block_to_helios(block).expect("block malformed"),
        ))
        .expect("could not send current block");

    let res = spawn_blocking(move || {
        remote_db
            .prefetch_from_revm_access_list(tx.access_list.clone())
            .expect("failed to prefetch state from access list");
        execute_tx(remote_db, tx)
    })
    .await
    .expect("failed to start tx execution")
    .expect("failed to execute transaction");

    println!(
        "{}",
        serde_json::to_string(&res).expect("failed to serialize result")
    );
}

fn execute_tx<DB: Database>(db: DB, tx: TxEnv) -> Result<ExecutionResult, EVMError<DB::Error>> {
    let mut evm = EVM::new();
    evm.database(db);
    evm.env.tx = tx;
    match evm.transact() {
        Ok(evm_res) => Ok(evm_res.result),
        Err(err) => Err(err),
    }
}
