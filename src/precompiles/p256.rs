use ethers::{
    abi::{decode, encode, ParamType, Token},
    types::U256,
};
use p256::elliptic_curve::{
    scalar::ScalarPrimitive,
    sec1::{Coordinates, EncodedPoint, FromEncodedPoint as _, ToEncodedPoint as _},
};
use revm::precompile::{
    Precompile, PrecompileError, PrecompileResult, PrecompileWithAddress, StandardPrecompileFn,
};

use crate::u64_to_address;

pub const ECMUL: PrecompileWithAddress = PrecompileWithAddress::new(
    u64_to_address(0x60700),
    Precompile::Standard(ecmul as StandardPrecompileFn),
);

const P256_INVALID_INPUT: PrecompileError =
    PrecompileError::CustomPrecompileError("unable to abi-decode input");
const P256_INVALID_POINT: PrecompileError = PrecompileError::CustomPrecompileError("invalid point");
const P256_INVALID_SCALAR: PrecompileError =
    PrecompileError::CustomPrecompileError("invalid scalar");

// function ecmul(uint256 x, uint256 y, unint256 s) returns (uint256 x, uint256 y);
fn ecmul(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas_used = 10000 as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    let mut decoded = decode(
        &[
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Uint(256),
        ],
        input,
    )
    .map_err(|_| P256_INVALID_INPUT)?
    .into_iter();

    fn bigint_to_bytes(n: U256) -> [u8; 32] {
        let mut b = [0u8; 32];
        n.to_big_endian(&mut b);
        b
    }

    let x = decoded
        .next()
        .and_then(|t| t.into_uint())
        .map(bigint_to_bytes)
        .ok_or(P256_INVALID_INPUT)?;
    let y = decoded
        .next()
        .and_then(|t| t.into_uint())
        .map(bigint_to_bytes)
        .ok_or(P256_INVALID_INPUT)?;
    let s = decoded
        .next()
        .and_then(|t| t.into_uint())
        .map(bigint_to_bytes)
        .ok_or(P256_INVALID_INPUT)?;
    if decoded.next().is_some() {
        return Err(P256_INVALID_INPUT)?;
    }

    let point = Option::<p256::AffinePoint>::from(p256::AffinePoint::from_encoded_point(
        &EncodedPoint::<p256::NistP256>::from_affine_coordinates(&x.into(), &y.into(), false),
    ))
    .ok_or_else(|| P256_INVALID_POINT)?;
    let scalar: p256::Scalar =
        Option::<ScalarPrimitive<p256::NistP256>>::from(
            ScalarPrimitive::<p256::NistP256>::from_bytes(&s.into()),
        )
        .ok_or_else(|| P256_INVALID_SCALAR)?
        .into();

    let result = (point * scalar).to_encoded_point(false);
    let (x, y) = match result.coordinates() {
        Coordinates::Identity => Default::default(),
        Coordinates::Uncompressed { x, y } => (U256::from_big_endian(x), U256::from_big_endian(y)),
        Coordinates::Compact { .. } | Coordinates::Compressed { .. } => {
            unreachable!("encoded as uncompressed")
        }
    };

    Ok((gas_used, encode(&[Token::Uint(x), Token::Uint(y)])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecmul() {
        let (_, output) = ecmul(
            &encode(&[
                Token::Uint(
                    "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" // x = G_X
                        .parse()
                        .unwrap(),
                ),
                Token::Uint(
                    "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5" // y = G_y
                        .parse()
                        .unwrap(),
                ),
                Token::Uint(
                    "0x8644bdcd959bb0e920230c9140171e779a4b03199a369201b14df7c82a223d7b" // random scalar
                        .parse()
                        .unwrap(),
                ),
            ]),
            10_000,
        )
        .unwrap();
        let mut decoded = decode(&[ParamType::Uint(256), ParamType::Uint(256)], &output)
            .unwrap()
            .into_iter();
        let ox = decoded.next().unwrap().into_uint().unwrap();
        let oy = decoded.next().unwrap().into_uint().unwrap();
        assert_eq!(
            ox,
            "0x44af9566a0a33d149e978e6c389d7ee6d01391f0fb4619d8af88c04e8ff2d53b" // public key x
                .parse()
                .unwrap()
        );
        assert_eq!(
            oy,
            "0x3296279e288a50ede07301f9ad983cb674036c6f25e368f96505b449d1e66ab9" // public key y
                .parse()
                .unwrap()
        );
    }
}
