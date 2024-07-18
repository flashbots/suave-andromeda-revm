use revm::precompile::{
    Precompile, PrecompileError, PrecompileResult, PrecompileWithAddress, StandardPrecompileFn,
};
use sha2::{Digest, Sha512};

use crate::u64_to_address;

pub const SHA512: PrecompileWithAddress = PrecompileWithAddress::new(
    u64_to_address(0x50700),
    Precompile::Standard(hash_sha512 as StandardPrecompileFn),
);

const INVALID_INPUT: PrecompileError = PrecompileError::CustomPrecompileError("Invalid input!");

fn hash_sha512(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas_used = 10000 as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    if input.len() == 0 {
        return Err(INVALID_INPUT);
    }
    let output = Sha512::digest(input).to_vec();
    Ok((gas_used, output))
}
