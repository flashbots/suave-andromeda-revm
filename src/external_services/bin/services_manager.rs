use regex::Regex;

use clap::Parser;

use std::io::{Cursor, Error as IoError};

use tiny_http::{Request, Response, Server};

use suave_andromeda_revm::services_manager::{self, ServicesManager};

pub type CallResponse = Response<Cursor<Vec<u8>>>;
type HandlerFn =
    fn(&ServicesManagerHttpServer, sm: &mut ServicesManager, req: &mut Request) -> CallResponse;

#[derive(Parser)]
struct Cli {
    /// The rpc endpoint to connect to
    #[arg(short, long, default_value_t = String::from("redis://127.0.0.1:6379/"))]
    kv_redis_endpoint: String,
    #[arg(short, long, default_value_t = String::from("redis://127.0.0.1:6379/"))]
    pubsub_redis_endpoint: String,
    #[arg(short, long, default_value_t = String::from("0.0.0.0"))]
    host: String,
    #[arg(short, long, default_value_t = String::from("5605"))]
    port: String,
}

fn main() {
    let cli_args = Cli::parse();
    let server = ServicesManagerHttpServer::new(cli_args.host, cli_args.port);
    let mut sm = ServicesManager::new(services_manager::Config {
        kv_redis_endpoint: cli_args.kv_redis_endpoint,
        pubsub_redis_endpoint: cli_args.pubsub_redis_endpoint,
    });
    server.process_forever(&mut sm);
}

#[derive(Debug)]
enum ServerError {
    RouteNotFoundError,
    HttpRespError(IoError),
    HttpRecvError(IoError),
    Stop,
}

struct ServicesManagerHttpServer {
    server: Server,
    routes: Vec<(Regex, HandlerFn)>,
}

impl ServicesManagerHttpServer {
    pub fn new(host: String, port: String) -> Self {
        let server = Server::http(format!("{}:{}", &host, &port)).unwrap();

        let routes: Vec<(Regex, HandlerFn)> = vec![(
            Regex::new(r#"^/$"#).unwrap(),
            ServicesManagerHttpServer::handle_request,
        )];

        ServicesManagerHttpServer { server, routes }
    }

    pub fn handle_request(&self, sm: &mut ServicesManager, req: &mut Request) -> CallResponse {
        let mut buf = Vec::new();
        if let Err(e) = req.as_reader().read_to_end(&mut buf) {
            return Response::from_data(e.to_string()).with_status_code(402);
        }

        match sm.run(&buf) {
            Ok(resp_bytes) => Response::from_data(resp_bytes),
            Err(e) => {
                println!("-> {:?}", e);
                Response::from_data(format!("{:?}", e)).with_status_code(500)
            }
        }
    }

    pub fn process_one(&self, sm: &mut ServicesManager) -> Result<(), ServerError> {
        match self.server.recv() {
            Ok(mut req) => {
                let handler = (|| {
                    for (route_re, handler) in self.routes.iter() {
                        if route_re.is_match(req.url()) {
                            return Ok(handler);
                        }
                    }
                    Err(ServerError::RouteNotFoundError)
                })()?;

                let response = handler(self, sm, &mut req);
                println!("{:?} -> {:?}", req, &response.status_code());
                match req.respond(response) {
                    Err(e) => Err(ServerError::HttpRespError(e)),
                    Ok(_) => Ok(()),
                }
            }
            Err(e) => {
                if e.to_string() == "thread unblocked" {
                    return Err(ServerError::Stop);
                }
                Err(ServerError::HttpRecvError(e))
            }
        }
    }

    pub fn process_forever(&self, sm: &mut ServicesManager) {
        loop {
            match self.process_one(sm) {
                Ok(_) => (),
                Err(ServerError::RouteNotFoundError) => {
                    println!("incorrect route requested");
                }
                Err(ServerError::HttpRespError(e)) => {
                    println!("could not respond to request: {}", e);
                }
                Err(ServerError::HttpRecvError(e)) => {
                    println!("failure during recv: {}", e);
                }
                Err(ServerError::Stop) => return,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use reqwest::blocking::Client;
    use reth_primitives::Bytes;
    use revm::{
        self,
        primitives::{address, Address, Env, TxEnv},
        DatabaseCommit, InMemoryDB, Transact,
    };

    use ethers;
    use ethers::abi::{JsonAbi, Token};
    use ethers::contract::{BaseContract, Lazy};
    use ethers::types::U256;
    use std::{
        include_str,
        sync::{Arc, Barrier},
        thread,
        time::Duration,
    };

    use suave_andromeda_revm::new_andromeda_revm;

    pub static SAMPLE_JSON_ABI: Lazy<JsonAbi> = Lazy::new(|| {
        serde_json::from_str(include_str!(
            "../../out/ServicesSample.sol/StoreServiceSample.json"
        ))
        .unwrap()
    });

    pub static SAMPLE_ABI: Lazy<ethers::abi::Abi> = Lazy::new(|| {
        serde_json::from_str(include_str!(
            "../../out/ServicesSample.sol/StoreServiceSample.abi.json"
        ))
        .unwrap()
    });

    static ADDR_A: Address = address!("4838b106fce9647bdf1e7877bf73ce8b0bad5f97");

    #[test]
    fn simulate() -> Result<(), String> {
        let server = Arc::new(super::ServicesManagerHttpServer::new(
            String::from("0.0.0.0"),
            String::from("5605"),
        ));
        let server_handle_clone = server.clone();

        let thread_barrier = Arc::new(Barrier::new(2));
        let thread_barrier_clone = thread_barrier.clone();

        let server_thread = thread::spawn(move || {
            thread_barrier_clone.wait();
            let local_redis_endpoint = "redis://127.0.0.1:6379";
            let mut sm = super::ServicesManager::new(super::services_manager::Config {
                kv_redis_endpoint: local_redis_endpoint.into(),
                pubsub_redis_endpoint: local_redis_endpoint.into(),
            });
            server_handle_clone.process_forever(&mut sm);
        });

        thread_barrier.wait();

        let testc = Client::new();
        for _i in 0..10 {
            let testr = testc.get("http://127.0.0.1:5605").send();
            if let Err(e) = testr {
                if !e.is_connect() {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(500));
        }

        let mut db = InMemoryDB::default();

        let mut env = Env::default();

        /* Deploy the contract */

        let sample_contract_addr: Address = (|| {
            let mut evm = new_andromeda_revm(&mut db, &mut env, None);
            evm.context.env.tx = TxEnv {
                caller: ADDR_A,
                transact_to: revm::primitives::TransactTo::create(),
                data: revm::primitives::Bytes::from(SAMPLE_JSON_ABI.bytecode().unwrap().0),
                ..Default::default()
            };
            let exec_result = evm.transact().unwrap();
            assert!(exec_result.result.is_success());
            if let revm::primitives::ExecutionResult::Success { output, .. } = exec_result.result {
                if let revm::primitives::Output::Create(_code, contract_addr) = output {
                    evm.context.db.commit(exec_result.state);
                    return Ok(contract_addr.unwrap());
                }
            }
            Err("call did not result in create")
        })()?;

        let sample_contract_abi: BaseContract = BaseContract::from(SAMPLE_ABI.clone());

        /* Smaller integration tests */
        {
            /* Ping */
            let mut tmp_db = db.clone();
            let mut evm = new_andromeda_revm(&mut tmp_db, &mut env, None);
            let calldata = sample_contract_abi
                .encode("ping", Token::Bytes(vec![0x01, 0x42]))
                .unwrap();
            evm.context.env.tx = TxEnv {
                caller: ADDR_A,
                transact_to: revm::primitives::TransactTo::Call(sample_contract_addr),
                data: revm::primitives::Bytes::from(calldata.0),
                ..Default::default()
            };
            let exec_result = evm.transact().unwrap();
            assert!(exec_result.result.is_success());

            let output = exec_result.result.into_output().unwrap();
            let pong: ethers::abi::Bytes =
                sample_contract_abi.decode_output("ping", output).unwrap();
            assert_eq!(pong, ethers::abi::Bytes::from(vec![0x01, 0x42]));
        }

        {
            /* Test redis pubsub - requires redis running! */
            {
                let mut tmp_db = db.clone();
                let mut evm = new_andromeda_revm(&mut tmp_db, &mut env, None);
                let calldata = sample_contract_abi
                    .encode("push_message", Token::Bytes(vec![0x01, 0x42]))
                    .unwrap();
                evm.context.env.tx = TxEnv {
                    caller: ADDR_A,
                    transact_to: revm::primitives::TransactTo::Call(sample_contract_addr),
                    data: revm::primitives::Bytes::from(calldata.0),
                    ..Default::default()
                };
                let exec_result = evm.transact().unwrap();
                assert!(exec_result.result.is_success());
            }

            // Let the message propagate
            thread::sleep(Duration::from_millis(500));

            {
                let mut tmp_db = db.clone();
                let mut evm = new_andromeda_revm(&mut tmp_db, &mut env, None);
                let calldata = sample_contract_abi.encode("get_message", ()).unwrap();
                evm.context.env.tx = TxEnv {
                    caller: ADDR_A,
                    transact_to: revm::primitives::TransactTo::Call(sample_contract_addr),
                    data: revm::primitives::Bytes::from(calldata.0),
                    ..Default::default()
                };
                let exec_result = evm.transact().unwrap();
                assert!(exec_result.result.is_success());

                let output = exec_result.result.into_output().unwrap();
                let pong: ethers::abi::Bytes =
                    sample_contract_abi.decode_output("ping", output).unwrap();
                assert_eq!(pong, ethers::abi::Bytes::from(vec![0x01, 0x42]));
            }
        }

        /* More complex behaviour */
        {
            let mut tmp_db = db.clone();
            let mut evm = new_andromeda_revm(&mut tmp_db, &mut env, None);
            let calldata = sample_contract_abi
                .encode(
                    "addBundle",
                    ((
                        Token::Uint(U256::from(31)),
                        Token::Bytes(vec![0x13, 0x53]),
                        Token::Uint(U256::from_big_endian(&[0x50])),
                    ),),
                )
                .unwrap();
            evm.context.env.tx = TxEnv {
                caller: ADDR_A,
                transact_to: revm::primitives::TransactTo::Call(sample_contract_addr),
                data: revm::primitives::Bytes::from(calldata.0),
                ..Default::default()
            };
            let exec_result = evm.transact().unwrap().result;
            assert!(exec_result.is_success());

            let output = exec_result.into_output().unwrap();
            assert_eq!(output, Bytes::new());
        }

        {
            let mut tmp_db = db.clone();
            let mut evm = new_andromeda_revm(&mut tmp_db, &mut env, None);
            let calldata = sample_contract_abi
                .encode("getBundlesByHeight", (Token::Uint(U256::from(31)),))
                .unwrap();
            evm.context.env.tx = TxEnv {
                caller: ADDR_A,
                transact_to: revm::primitives::TransactTo::Call(sample_contract_addr),
                data: revm::primitives::Bytes::from(calldata.0),
                ..Default::default()
            };
            let exec_result = evm.transact().unwrap().result;
            assert!(exec_result.is_success());

            let output = exec_result.into_output().unwrap();
            assert_eq!(
                output,
                Bytes::from(ethers::abi::encode(&[
                    Token::Bool(true),
                    Token::Array(vec![Token::Tuple(vec![
                        Token::Uint(U256::from(31)),
                        Token::Bytes(vec![0x13, 0x53]),
                        Token::Uint(U256::from_big_endian(&[0x50])),
                    ])])
                ]))
            );
        }

        server.server.unblock();
        let _ = server_thread.join();

        Ok(())
    }
}
