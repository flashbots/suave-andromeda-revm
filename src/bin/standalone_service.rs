use clap::Parser;
use std::io;
// use tokio::task::spawn_blocking;

use helios::types::BlockTag;
use revm::primitives::TxEnv;
use witness_revm::StatefulExecutor;

#[derive(Parser)]
struct Cli {
    /// The rpc endpoint to connect to
    #[arg(short, long, default_value_t = String::from("http://127.0.0.1:8545"))]
    rpc: String,
}

#[tokio::main]
async fn main() {
    let cli_args = Cli::parse();
    let service = StatefulExecutor::new_with_rpc(cli_args.rpc.clone());

    // TODO: probably doesnt work due to async
    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("");

        // We support two commands: advance <block number> and execute <transaction json>
        if let Some((command, args)) = input.trim().split_once(' ') {
            if command == "advance" {
                if args == "latest" {
                    service
                        .advance(BlockTag::Latest)
                        .await
                        .expect("could not advance");
                } else {
                    match args.parse::<u64>() {
                        Ok(n) => {
                            service
                                .advance(BlockTag::Number(n))
                                .await
                                .expect("could not advance");
                        }
                        Err(_e) => {
                            println!("invalid command");
                        }
                    }
                }
            } else if command == "execute" {
                let tx: TxEnv = serde_json::from_str(args).expect("could not parse transaction");
                let res = service.execute(tx).expect("could not execute");
                println!(
                    "{}",
                    serde_json::to_string(&res).expect("failed to serialize result")
                );
            }
        } else {
            println!("invalid command");
            continue;
        }
    }
}
