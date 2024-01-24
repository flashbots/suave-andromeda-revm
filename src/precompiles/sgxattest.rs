use revm::precompile::{
    EnvPrecompileFn, Precompile, PrecompileError, PrecompileResult, PrecompileWithAddress,
    StandardPrecompileFn,
};
use revm::primitives::Env;

use ethers::abi::Token;
use ethers::types::H160;
use sha2::*;

use lazy_static::lazy_static;
use std::{collections::HashMap, sync::Mutex};
use std::{fs, fs::File, io::Read, io::Write, path::Path};

use crate::u64_to_address;

pub const ATTEST: PrecompileWithAddress = PrecompileWithAddress::new(
    u64_to_address(0x40700),
    Precompile::Env(sgxattest_run as EnvPrecompileFn),
);

pub const VOLATILESET: PrecompileWithAddress = PrecompileWithAddress::new(
    u64_to_address(0x40701),
    Precompile::Env(sgxattest_volatile_set as EnvPrecompileFn),
);

pub const VOLATILEGET: PrecompileWithAddress = PrecompileWithAddress::new(
    u64_to_address(0x40702),
    Precompile::Env(sgxattest_volatile_get as EnvPrecompileFn),
);

pub const RANDOM: PrecompileWithAddress = PrecompileWithAddress::new(
    u64_to_address(0x40703),
    Precompile::Standard(sgxattest_random as StandardPrecompileFn),
);

fn sgxattest_random(_input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas_used = 10000 as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas);
    } else {
        let mut file = std::fs::File::open("/dev/urandom").unwrap();
        let mut buffer = [0; 32];
        file.read(&mut buffer[..]).unwrap();
        return Ok((gas_used, buffer.to_vec()));
    }
}

// We will store volatile values in an in-memory hashmap.
// The keys are [20 byte address][32 bytes application defined]
lazy_static! {
    static ref VOLATILE: Mutex<HashMap<[u8; 52], [u8; 32]>> = Mutex::new(HashMap::new());
}

const SGX_ATTESTATION_FAILED: PrecompileError =
    PrecompileError::CustomPrecompileError("gramnie sgx attestation failed");

const SGX_VOLATILE_KEY_MISSING: PrecompileError =
    PrecompileError::CustomPrecompileError("key does not exist in volatile storage");

fn sgxattest_volatile_set(input: &[u8], gas_limit: u64, env: &Env) -> PrecompileResult {
    let gas_used = 10000 as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas);
    } else if input.len() != 64 {
        return Err(SGX_ATTESTATION_FAILED);
    } else {
        let mut vol = VOLATILE.lock().unwrap();
        let domain_sep = env.msg.caller;
        let mut key: [u8; 52] = [0; 52];
        key[0..20].copy_from_slice(&domain_sep.0 .0);
        key[20..52].copy_from_slice(&input[0..32]);
        let mut val: [u8; 32] = [0; 32];
        val.copy_from_slice(&input[32..64]);
        vol.insert(key, val);
        return Ok((gas_used, vec![]));
    }
}

fn sgxattest_volatile_get(input: &[u8], gas_limit: u64, env: &Env) -> PrecompileResult {
    let gas_used = 10000 as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas);
    } else if input.len() != 32 {
        return Err(SGX_ATTESTATION_FAILED);
    } else {
        let vol = VOLATILE.lock().unwrap();
        let domain_sep = env.msg.caller;
        let mut key: [u8; 52] = [0; 52];
        key[0..20].copy_from_slice(&domain_sep.0 .0);
        key[20..52].copy_from_slice(&input[0..32]);
        if let Some(val) = vol.get(&key) {
            return Ok((gas_used, val.to_vec()));
        }
        return Err(SGX_VOLATILE_KEY_MISSING);
    }
}

fn sgxattest_run(input: &[u8], gas_limit: u64, env: &Env) -> PrecompileResult {
    let gas_used = 10000 as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas);
    } else {
        // Attestation available
        if !Path::new("/dev/attestation/quote").exists() {
            return Err(SGX_ATTESTATION_FAILED);
        }

        // Write some user report data
        let mut f = match File::create("/dev/attestation/user_report_data") {
            Ok(f) => f,
            Err(error) => {
                panic!("sgx open failed {:?}", error);
            }
        };

        // User report data = Hash( Caller || Application input)
        let domain_sep = env.msg.caller;
        let message: &[u8] = &ethers::abi::encode(&[
            Token::Address(H160(domain_sep.0 .0)),
            Token::Bytes(input.to_vec()),
        ]);
        let hash = sha2::Sha256::digest(message).to_vec();

        match f.write_all(&hash) {
            Ok(()) => (),
            Err(error) => {
                panic!("sgx write failed {:?}", error);
            }
        };
        drop(f);

        // Get the extracted attestation quote
        let quote = match fs::read("/dev/attestation/quote") {
            Ok(quote) => quote,
            Err(error) => {
                panic!("sgx read failed {:?}", error);
            }
        };

        //dbg!(&quote);

        // Copy the attestation quote to our output directory
        return Ok((gas_used, quote));
    }
}
