use revm::{
    primitives::{address, AccountInfo, Address, Bytecode, Bytes, Env, TxEnv},
    InMemoryDB, Transact,
};

use ethers::abi::{ethabi, parse_abi, Token};
use ethers::contract::{BaseContract, Lazy};
use std::include_str;

use suave_andromeda_revm::new_andromeda_revm;

fn main() -> eyre::Result<()> {
    // Read from the untrusted host via a Gramine-mapped file
    simulate()?;
    Ok(())
}

pub static ANDROMEDA_CODE: Lazy<Bytes> = Lazy::new(|| {
    include_str!("examples_Andromeda_sol_Andromeda.bin")
        .parse()
        .unwrap()
});

pub static ADDR_A: Address = address!("4838b106fce9647bdf1e7877bf73ce8b0bad5f97");
pub static ADDR_B: Address = address!("F2d01Ee818509a9540d8324a5bA52329af27D19E");

fn get_code() -> eyre::Result<Bytes> {
    // This is gross, but I'm trying to remove the "constructor" from the bytecode
    // generated from solc
    let mut db = InMemoryDB::default();
    let info = AccountInfo {
        code: Some(Bytecode::new_raw((*ANDROMEDA_CODE.0).into())),
        ..Default::default()
    };
    db.insert_account_info(ADDR_B, info);

    let mut env = Env::default();
    env.tx = TxEnv {
        caller: ADDR_A,
        transact_to: revm::primitives::TransactTo::Call(ADDR_B),
        data: revm::primitives::Bytes::from(ANDROMEDA_CODE.0.clone()),
        ..Default::default()
    };

    let mut evm = new_andromeda_revm(&mut db, &mut env, None);

    let result = evm.transact()?;
    //dbg!(&result);
    match result.result.output() {
        Some(o) => Ok(o.clone()),
        _ => {
            todo!()
        }
    }
}

fn simulate() -> eyre::Result<()> {
    let mut db = InMemoryDB::default();

    let code = get_code()?;
    let info = AccountInfo {
        code: Some(Bytecode::new_raw(code)),
        ..Default::default()
    };
    db.insert_account_info(ADDR_B, info);

    let mut env = Env::default();
    env.tx = TxEnv {
        caller: ADDR_A,
        transact_to: revm::primitives::TransactTo::Call(ADDR_B),
        data: revm::primitives::Bytes::from(ANDROMEDA_CODE.0.clone()),
        ..Default::default()
    };

    let mut evm = new_andromeda_revm(&mut db, &mut env, None);

    let abi = BaseContract::from(parse_abi(&[
        "function localRandom() returns (bytes32)",
        "function attestSgx(bytes) returns (bytes)",
        "function volatileSet(bytes32,bytes32)",
        "function volatileGet(bytes32) returns (bytes32)",
        "function sha512(bytes) returns (bytes)",
    ])?);

    //////////////////////////
    // Suave.localRandom()
    //////////////////////////
    {
        let calldata = abi.encode("localRandom", ())?;
        evm.context.env.tx = TxEnv {
            caller: ADDR_A,
            transact_to: revm::primitives::TransactTo::Call(ADDR_B),
            data: revm::primitives::Bytes::from(calldata.0),
            ..Default::default()
        };
        let result = evm.transact()?;
        dbg!(&result.result.output());
    }

    //////////////////////////
    // Suave.attestSgx("hello")
    //////////////////////////
    {
        let calldata = abi.encode("attestSgx", (Token::Bytes("hello".as_bytes().to_vec()),))?;
        evm.context.env.tx = TxEnv {
            transact_to: revm::primitives::TransactTo::Call(ADDR_B),
            data: revm::primitives::Bytes::from(calldata.0),
            ..Default::default()
        };
        let result = evm.transact()?;
        let decoded = ethabi::decode(&[ethabi::ParamType::Bytes], result.result.output().unwrap())?;
        let quote = match &decoded[0] {
            Token::Bytes(b) => b,
            _ => todo!(),
        };
        let hex: String = quote.iter().map(|byte| format!("{:02x}", byte)).collect();
        dbg!(hex);
    }

    //////////////////////////
    // Suave.volatileSet/Get
    //////////////////////////
    let mykey = "deadbeefdeadbeefdeadbeefdeadbeef".as_bytes().to_vec();
    let myval = "cafebabecafebabecafebabecafebabe".as_bytes().to_vec();
    {
        let calldata = abi.encode(
            "volatileSet",
            (Token::FixedBytes(mykey.clone()), Token::FixedBytes(myval)),
        )?;
        evm.context.env.tx = TxEnv {
            caller: ADDR_A,
            transact_to: revm::primitives::TransactTo::Call(ADDR_B),
            data: revm::primitives::Bytes::from(calldata.0),
            ..Default::default()
        };
        let _result = evm.transact()?;
        //dbg!(result);
    }
    {
        let calldata = abi.encode("volatileGet", (Token::FixedBytes(mykey),))?;
        evm.context.env.tx = TxEnv {
            caller: ADDR_A,
            transact_to: revm::primitives::TransactTo::Call(ADDR_B),
            data: revm::primitives::Bytes::from(calldata.0),
            ..Default::default()
        };
        let result = evm.transact()?;
        let decoded = ethabi::decode(
            &[ethabi::ParamType::FixedBytes(32)],
            result.result.output().unwrap(),
        )?;
        let val = match &decoded[0] {
            Token::FixedBytes(b) => b,
            _ => todo!(),
        };
        dbg!(std::str::from_utf8(val).unwrap());
    }

    //////////////////////////
    // Suave.sha512
    //////////////////////////
    {
        let calldata = abi.encode("sha512", (Token::Bytes("test".as_bytes().to_vec()),))?;
        evm.context.env.tx = TxEnv {
            caller: ADDR_A,
            transact_to: revm::primitives::TransactTo::Call(ADDR_B),
            data: revm::primitives::Bytes::from(calldata.0),
            ..Default::default()
        };
        let result = evm.transact()?;
        let decoded = ethabi::decode(&[ethabi::ParamType::Bytes], result.result.output().unwrap())?;
        let hash = match &decoded[0] {
            Token::Bytes(b) => b,
            _ => todo!(),
        };
        let hex: String = hash.iter().map(|byte| format!("{:02x}", byte)).collect();
        dbg!(hex);
    }
    Ok(())
}
