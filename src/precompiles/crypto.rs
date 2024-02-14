use sha2::{Sha512, Digest};
use revm::precompile::{
    Precompile, PrecompileError, PrecompileResult, PrecompileWithAddress,
    StandardPrecompileFn,
};


use crate::u64_to_address;

pub const SHA512: PrecompileWithAddress = PrecompileWithAddress::new(
    u64_to_address(0x50700),
    Precompile::Standard(crypto_sha512 as StandardPrecompileFn),
);

const HASH512_FAILED: PrecompileError =
    PrecompileError::CustomPrecompileError("failed hashing empty input!");


fn crypto_sha512(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas_used = 10000 as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas);
    } else if input.len() < 1 {
        return Err(HASH512_FAILED);
    } else {
        let mut hasher = Sha512::new();
        hasher.update(input);
        let result = hasher.finalize();
        return Ok((gas_used, result.to_vec()));
    }
}