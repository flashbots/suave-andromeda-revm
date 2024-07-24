use ethers::abi::{decode, encode, ParamType, Token};
use reth_primitives::Bytes;
use revm::{
    precompile::{
        Precompile, PrecompileError, PrecompileResult, PrecompileWithAddress, StandardPrecompileFn,
    },
    primitives::{PrecompileErrors, PrecompileOutput},
};

use crate::u64_to_address;

pub const GENERATE_CERTIFICATE: PrecompileWithAddress = PrecompileWithAddress(
    u64_to_address(0x70700),
    Precompile::Standard(generate_certificate as StandardPrecompileFn),
);

const X509_INVALID_INPUT: &'static str = "unable to abi-decode input";
const X509_INVALID_KEY: &'static str = "invalid key provided (must be PKCS8 DER encoded)";
const X509_CERTGEN_FAILED: &'static str = "certificate generation failed";

// function generate_certificate(bytes sk, string domain, string subject) returns (bytes certificate);
fn generate_certificate(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    let gas_used = 10000 as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas.into());
    }

    let mut decoded = decode(
        &[ParamType::Bytes, ParamType::String, ParamType::String],
        input,
    )
    .map_err(|_| PrecompileErrors::Error(PrecompileError::Other(X509_INVALID_INPUT.into())))?
    .into_iter();

    let sk = decoded
        .next()
        .and_then(|t| t.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::Other(
            X509_INVALID_INPUT.into(),
        )))?;
    let domain = decoded
        .next()
        .and_then(|t| t.into_string())
        .ok_or(PrecompileErrors::Error(PrecompileError::Other(
            X509_INVALID_INPUT.into(),
        )))?;
    let subject = decoded
        .next()
        .and_then(|t| t.into_string())
        .ok_or(PrecompileErrors::Error(PrecompileError::Other(
            X509_INVALID_INPUT.into(),
        )))?;
    if decoded.next().is_some() {
        return Err(PrecompileErrors::Error(PrecompileError::Other(
            X509_INVALID_INPUT.into(),
        )))?;
    }

    let kp: rcgen::KeyPair = sk
        .try_into()
        .map_err(|_| PrecompileErrors::Error(PrecompileError::Other(X509_INVALID_KEY.into())))?;
    let mut unsigned_cert = rcgen::CertificateParams::new(vec![domain])
        .map_err(|_| PrecompileErrors::Error(PrecompileError::Other(X509_CERTGEN_FAILED.into())))?;
    unsigned_cert
        .distinguished_name
        .push(rcgen::DnType::CommonName, subject);
    let cert = unsigned_cert
        .self_signed(&kp)
        .map_err(|_| PrecompileErrors::Error(PrecompileError::Other(X509_CERTGEN_FAILED.into())))?;

    Ok(PrecompileOutput::new(
        gas_used,
        encode(&[Token::Bytes(cert.der().to_vec())]).into(),
    ))
}

#[cfg(test)]
mod tests {
    use reth_primitives::hex::FromHex as _;
    use webpki::types::CertificateDer;

    use super::*;

    #[test]
    fn test_generate_certificate() {
        let output = generate_certificate(
            &encode(&[
                Token::Bytes(Vec::<u8>::from_hex("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420b4e65cc60aeec9677e719c534c0df52281f6b0911d60ed49b9200c8afe47aa4da14403420004ab7c84edbebfdc5e2505dcd962fe0eebc30abebd04d7e469e97bcfd690870e0df5fffe45f50e0c4b440a7571c7914ac7922c6058eda2f1b75e11263e3f7da5db").unwrap()),
                Token::String("example.com".into()),
                Token::String("example.com".into()),
            ]).into(),
            10_000,
        )
        .unwrap();
        let mut decoded = decode(&[ParamType::Bytes], &output.bytes).unwrap();
        let cert_der = CertificateDer::from(decoded.pop().unwrap().into_bytes().unwrap());
        let _ = webpki::anchor_from_trusted_cert(&cert_der).unwrap(); // ensure it parses
    }
}
