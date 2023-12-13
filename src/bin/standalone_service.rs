use clap::Parser;
use std::io;

use witness_revm::StatefulExecutor;

#[derive(Parser)]
struct Cli {
    /// The rpc endpoint to connect to
    #[arg(short, long, default_value_t = String::from("http://127.0.0.1:8545"))]
    rpc: String,
    #[arg(short, long, default_value_t = false)]
    trace: bool,
}

#[tokio::main]
async fn main() {
    let cli_args = Cli::parse();
    let mut service = StatefulExecutor::new_with_rpc(cli_args.rpc.clone());

    // TODO: probably doesnt work due to async
    loop {
        let mut input_buf = String::new();
        io::stdin().read_line(&mut input_buf).expect("");

        match service
            .execute_command(input_buf.trim(), cli_args.trace)
            .await
        {
            Ok(res) => println!("{:?}", res),
            Err(e) => println!("{:?}", e),
        }
    }
}
