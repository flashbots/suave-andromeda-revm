use revm::precompile::PrecompileWithAddress;
use revm::primitives::{
    Bytes, Precompile, PrecompileError, PrecompileErrors, PrecompileOutput, PrecompileResult,
    StandardPrecompileFn,
};
use sha2::{Digest, Sha512};

use crate::u64_to_address;

pub const SHA512: PrecompileWithAddress = PrecompileWithAddress(
    u64_to_address(0x50700),
    Precompile::Standard(hash_sha512 as StandardPrecompileFn),
);

const INVALID_INPUT: &'static str = "Invalid input!";

fn hash_sha512(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    let gas_used = 10000 as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas.into());
    }
    if input.len() == 0 {
        return Err(PrecompileErrors::Error(PrecompileError::Other(
            INVALID_INPUT.into(),
        )));
    }
    let output = Sha512::digest(input).to_vec().into();
    Ok(PrecompileOutput::new(gas_used, output))
}
