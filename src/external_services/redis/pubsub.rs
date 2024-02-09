use std::collections::HashMap;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ethers::abi::{encode, parse_abi, Address, Contract, Detokenize, Token};
use ethers::contract::{BaseContract, Lazy};
use ethers::types::Bytes;

pub static REDIS_PUBSUB_ABI: Lazy<BaseContract> = Lazy::new(|| {
    let contract: Contract =
        serde_json::from_str(include_str!("../../../out/Pubsub.sol/RedisPubsub.abi.json")).unwrap();
    BaseContract::from(contract)
});

pub fn pubsub_contract() -> BaseContract {
    REDIS_PUBSUB_ABI.clone()
}

pub fn redis_subscriber_contract() -> BaseContract {
    parse_abi(&["function onRedisMessage(string memory topic, bytes memory msg) external"])
        .unwrap()
        .into()
}

#[derive(Debug)]
pub enum RedisPubsubError {
    Error(String),
    InstantiationError(String),
    StreamError(String),
    InvalidCall,
    InvalidCalldata,
    ConnectionFailure,
}

use redis::{self, Commands, PubSub};
use reth_primitives::hex::ToHex;

use crate::external_services::common::CallContext;

struct RedisSusbscriber<'a> {
    pubsub: PubSub<'a>,
    subscribers: HashMap<String, Address>,
}

pub struct RedisPubsub {
    client: redis::Client,
    pub pubsub_abi: BaseContract,

    subscribe_tx: Sender<(String, Address)>,
    unsubscribe_tx: Sender<(String, Address)>,

    temp_messages: Arc<Mutex<HashMap<(String, Address), Vec<Vec<u8>>>>>,

    publish_fn_abi: ethers::abi::Function,
    get_message_fn_abi: ethers::abi::Function,
    subscribe_fn_abi: ethers::abi::Function,
    unsubscribe_fn_abi: ethers::abi::Function,
}

impl RedisPubsub {
    pub fn new() -> Self {
        let pubsub_contract = REDIS_PUBSUB_ABI.clone();
        let pubsub_abi = pubsub_contract.abi();

        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let client_clone = client.clone();

        let (subscribe_tx, subscribe_rx) = channel::<(String, Address)>();
        let (unsubscribe_tx, unsubscribe_rx) = channel::<(String, Address)>();

        let (notify_tx, notify_rx) = channel::<(String, Address, Vec<u8>)>();

        let temp_messages = Arc::new(Mutex::new(HashMap::new()));
        let temp_messages_clone = temp_messages.clone();

        thread::spawn(move || {
            // Qing messages incoming on notify_rx into temp_messages for later consumption
            while let Ok((topic, addr, msg_data)) = notify_rx.recv() {
                println!("received msg {} {} {:?}", topic, addr, msg_data);
                let mut messages_map = temp_messages_clone.lock().unwrap();
                match messages_map.get_mut(&(topic.clone(), addr)) {
                    None => {
                        messages_map.insert((topic, addr), vec![msg_data]);
                    }
                    Some(messages_vec) => {
                        if messages_vec.len() < 50
                        /* max buffered messages */
                        {
                            messages_vec.push(msg_data);
                        }
                    }
                }
            }
        });

        // Http mevm callbacks
        // For now we'll store the messages in memeory and let clients fetch via get_message(topic)

        /*
            let mevm_client = ReqwestClient::new();

            thread::spawn(move || {
                let redis_subscriber_abi = redis_subscriber_contract();
                while let Ok((topic, addr, msg_data)) = notify_rx.recv() {
                    /* Send to mevm! */
                    let calldata = redis_subscriber_abi
                        .encode(
                            "onRedisMessage",
                            (Token::String(topic), Token::Bytes(msg_data)),
                        )
                        .unwrap();

                    let tx_env = revm_primitives::TxEnv {
                        caller: revm_primitives::Address::ZERO,
                        gas_limit: 21000000,
                        gas_price: revm_primitives::U256::ZERO,
                        transact_to: revm_primitives::TransactTo::Call(addr.0.into()),
                        value: revm_primitives::U256::ZERO,
                        data: revm_primitives::Bytes(calldata.0.into()),
                        nonce: None,
                        chain_id: None,
                        access_list: Vec::new(),
                        gas_priority_fee: None,
                        blob_hashes: Vec::new(),
                        max_fee_per_blob_gas: None,
                    };

                    let serialized_tx_env = serde_json::to_string(&tx_env);
                    if let Err(e) = serialized_tx_env {
                        println!("{}", e);
                        continue;
                    }

                    let res = mevm_client
                        .post("http://127.0.0.1:5556/")
                        .body(serialized_tx_env.unwrap())
                        .send()
                        .unwrap();
                    println!("{:?}", res);
                }
            });
        */

        thread::spawn(move || {
            // Subscribing and unsubscribing based on [un]subscribe_rx
            // And then a blocking-with-timeout message poll

            let mut conn = client_clone.get_connection().unwrap();

            let mut subscriber = RedisSusbscriber {
                pubsub: conn.as_pubsub(),
                subscribers: HashMap::new(),
            };

            subscriber
                .pubsub
                .set_read_timeout(Some(Duration::from_millis(10)))
                .unwrap();

            loop {
                while let Ok((topic, addr)) = subscribe_rx.try_recv() {
                    match subscriber.subscribers.get_mut(&topic) {
                        None => {
                            subscriber.subscribers.insert(topic.clone(), addr);
                            println!("subscribing to {} {}", topic, addr);
                            let _ = subscriber.pubsub.subscribe(&topic).map_err(|e| {
                                println!("{}", e);
                                RedisPubsubError::ConnectionFailure
                            });
                        }
                        Some(sub) => {
                            if sub != &addr {
                                println!("pubsub: invalid subscribe to {} requested {} would shadow previous subscription {}", topic, sub, addr);
                                assert!(sub == &addr);
                            }
                        }
                    }
                }

                while let Ok((topic, addr)) = unsubscribe_rx.try_recv() {
                    match subscriber.subscribers.get_mut(&topic) {
                        None => {}
                        Some(sub) => {
                            if sub != &addr {
                                println!("pubsub: invalid unsubscribe to {} requested {} would shadow previous subscription {}", topic, sub, addr);
                                assert!(sub == &addr);
                            }
                            let _ = subscriber.pubsub.unsubscribe(topic).map_err(|e| {
                                println!("{}", e);
                            });
                        }
                    };
                }

                /* TODO: set timeout for resubscribe and process messages in batches */
                match subscriber.pubsub.get_message() {
                    Err(_e) => {
                        if _e.is_timeout() {
                            continue;
                        }
                        println!("{}", _e);
                    }
                    Ok(msg) => {
                        println!("new message {:?}", msg);
                        let topic = msg.get_channel_name();
                        if let Some(sub) = subscriber.subscribers.get(topic) {
                            notify_tx
                                .send((
                                    String::from(topic),
                                    sub.clone(),
                                    msg.get_payload_bytes().to_vec(),
                                ))
                                .unwrap();
                        } else {
                            // Unexpected!
                            subscriber.pubsub.unsubscribe(topic).unwrap();
                        }
                    }
                };
            }
        });

        RedisPubsub {
            client,
            pubsub_abi: pubsub_contract.to_owned(),
            subscribe_tx,
            unsubscribe_tx,
            temp_messages,
            publish_fn_abi: pubsub_abi.function("publish").unwrap().clone(),
            get_message_fn_abi: pubsub_abi.function("get_message").unwrap().clone(),
            subscribe_fn_abi: pubsub_abi.function("subscribe").unwrap().clone(),
            unsubscribe_fn_abi: pubsub_abi.function("unsubscribe").unwrap().clone(),
        }
    }

    pub fn publish(
        &mut self,
        context: CallContext,
        inputs: &[u8],
    ) -> Result<ethers::abi::Bytes, RedisPubsubError> {
        let (mut topic, msg): (String, Bytes) = Detokenize::from_tokens(
            self.publish_fn_abi
                .decode_input(inputs)
                .map_err(|_e| RedisPubsubError::InvalidCalldata)?,
        )
        .map_err(|_e| RedisPubsubError::InvalidCalldata)?;

        topic = format!("{}:{}", context.1.encode_hex::<String>(), &topic);

        let mut conn = self.client.get_connection().map_err(|e| {
            println!("{}", e);
            RedisPubsubError::ConnectionFailure
        })?;

        let r_msg: &[u8] = &msg;
        conn.publish(topic, &r_msg).map_err(|e| {
            println!("{}", e);
            RedisPubsubError::ConnectionFailure
        })?;

        Ok(vec![])
    }

    pub fn get_message(
        &mut self,
        context: CallContext,
        inputs: &[u8],
    ) -> Result<ethers::abi::Bytes, RedisPubsubError> {
        let mut topic: String = Detokenize::from_tokens(
            self.get_message_fn_abi
                .decode_input(inputs)
                .map_err(|_e| RedisPubsubError::InvalidCalldata)?,
        )
        .map_err(|_e| RedisPubsubError::InvalidCalldata)?;

        topic = format!("{}:{}", context.1.encode_hex::<String>(), &topic);

        let mut messages_map = self.temp_messages.lock().unwrap();
        println!("getting for {} from msgs {:?}", topic, messages_map);
        match messages_map.get_mut(&(topic, context.1)) {
            None => Ok(encode(&[Token::Bytes(vec![])])),
            Some(messages_vec) => match messages_vec.first_mut() {
                None => Ok(encode(&[Token::Bytes(vec![])])),
                Some(msg_data) => {
                    let ret_data = Token::Bytes(msg_data.clone());
                    messages_vec.remove(0);
                    Ok(encode(&[ret_data]))
                }
            },
        }
    }

    pub fn subscribe(
        &mut self,
        context: CallContext,
        inputs: &[u8],
    ) -> Result<ethers::abi::Bytes, RedisPubsubError> {
        let mut topic: String = Detokenize::from_tokens(
            self.subscribe_fn_abi
                .decode_input(inputs)
                .map_err(|_e| RedisPubsubError::InvalidCalldata)?,
        )
        .map_err(|_e| RedisPubsubError::InvalidCalldata)?;

        topic = format!("{}:{}", context.1.encode_hex::<String>(), &topic);

        self.subscribe_tx.send((topic, context.1)).unwrap();

        Ok(vec![])
    }

    pub fn unsubscribe(
        &mut self,
        context: CallContext,
        inputs: &[u8],
    ) -> Result<ethers::abi::Bytes, RedisPubsubError> {
        let mut topic: String = Detokenize::from_tokens(
            self.unsubscribe_fn_abi
                .decode_input(inputs)
                .map_err(|_e| RedisPubsubError::InvalidCalldata)?,
        )
        .map_err(|_e| RedisPubsubError::InvalidCalldata)?;

        topic = format!("{}:{}", context.1.encode_hex::<String>(), &topic);

        self.unsubscribe_tx.send((topic, context.1)).unwrap();

        Ok(vec![])
    }
}
