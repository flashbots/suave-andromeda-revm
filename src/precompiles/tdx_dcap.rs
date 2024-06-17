use revm::precompile::{
    Precompile, PrecompileError, PrecompileErrors, PrecompileOutput, PrecompileResult,
    PrecompileWithAddress, StandardPrecompileFn,
};

use std::ffi;

use ethers::abi::{encode_packed, Detokenize, Function, Token};
use ethers::types::H160;
use ethers::utils::keccak256;
use sha2::*;

use lazy_static::lazy_static;
use std::{collections::HashMap, sync::Mutex};
use std::{fs, fs::File, io::Read, io::Write, path::Path};

use crate::{u64_to_address, QuoteVerificationLibrary};

use ethers::abi::{encode, Bytes as AbiBytes, Contract};
use ethers::contract::{BaseContract, Lazy};
use ethers::types::{Address, H256};

use reth_primitives::Bytes;
use revm::primitives::{Address as RevmAddress, Env};

pub const VERIFY_QUOTE: PrecompileWithAddress = PrecompileWithAddress(
    u64_to_address(0x40800),
    Precompile::Standard(tgx_verify_quote_run as StandardPrecompileFn),
);

// Redefined here to avoid having to import from external services
pub static TDX_DCAP_ABI: Lazy<BaseContract> = Lazy::new(|| {
    let contract: Contract =
        serde_json::from_str(include_str!("../out/TdxDcap.sol/TDX_DCAP.abi.json")).unwrap();
    BaseContract::from(contract)
});

pub static VERIFY_QUOTE_ABI: Lazy<Function> = Lazy::new(|| {
    TDX_DCAP_ABI
        .abi()
        .function("verifyQuote")
        .expect("verifyQuote signature not available in TDX DCAP abi")
        .clone()
});

const INPUTS_TOO_BIG: &'static str = "inputs passed in are unreasonably big";
const INCORRECT_INPUTS: &'static str = "incorrect inputs passed in";

fn tgx_verify_quote_run(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    let gas_used = 10000 as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas.into());
    }

    const max_quote_size: usize = 1 << 14; // 16kiB
    if input.len() > max_quote_size {
        return Err(PrecompileErrors::Error(PrecompileError::Other(
            INPUTS_TOO_BIG.into(),
        )));
    }

    let (quote, pckCertPem, pckCrlPem, tcbInfoJson, qeIdentityJson): (
        AbiBytes,
        String,
        String,
        String,
        String,
    ) =
        Detokenize::from_tokens(VERIFY_QUOTE_ABI.decode_input(input).map_err(|_e| {
            PrecompileErrors::Error(PrecompileError::Other(INCORRECT_INPUTS.into()))
        })?)
        .map_err(|_e| PrecompileErrors::Error(PrecompileError::Other(INCORRECT_INPUTS.into())))?;

    let pckCertCstr = ffi::CString::new(pckCertPem).unwrap();
    let pckCrlCstr = ffi::CString::new(pckCrlPem).unwrap();

    let tcbInfoCstr = ffi::CString::new(tcbInfoJson).unwrap();
    let qeIdentityCstr = ffi::CString::new(qeIdentityJson).unwrap();

    unsafe {
        let status = QuoteVerificationLibrary::sgxAttestationVerifyQuote(
            quote.as_ptr(),
            quote.len() as u32,
            pckCertCstr.as_ptr(),
            pckCrlCstr.as_ptr(),
            tcbInfoCstr.as_ptr(),
            qeIdentityCstr.as_ptr(),
        );

        return Ok(PrecompileOutput::new(
            10000,
            encode(&[Token::Uint(status.into())]).into(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::FromHex;

    #[test]
    fn verify_sample_quote() -> Result<(), String> {
        let input = encode(&[
            Token::Bytes(Vec::from_hex(QUOTE_HEX).unwrap()),
            Token::String(PCK_CERT.to_string()),
            Token::String(PCK_CRL.to_string()),
            Token::String(TCB_INFO.to_string()),
            Token::String(QE_IDENTITY.to_string()),
        ]);
        let res = tgx_verify_quote_run(&input.into(), 10000).expect("call did not succeed");
        assert_eq!(res.bytes, encode(&[Token::Uint(U256::ZERO)]));

        // TODO: add a failing example (mismatch TCB, QEIdentity, invalid PCK)

        Ok(())
    }

    const QUOTE_HEX: &str = "030002000000000000000300939a7233f79c4ca9940a0db3957f0607ef8f440cf9a1b29e378f44ede54fb29b3b263edf0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a020000021a1375acdfc4520ade2f984b051e59a54e2892b24d3aa98e543b7b49eef2a375a7b5bafd1f1972e604fd799d4a01e2e422a52558768606daade2b17a6313ee5b0207744f06b8ded78917b4b4c80e6a12600579d54a3079190560d76db5d95b3d4e8fcd804f4531d9d90610a8bbced39f297f8892cba97612fd8ef181fcf98c00030000000101000000000000000000d182b18c0000000000000000000000000000000000000000000000000000000070c8cbf48bd76eab9c8126ce95e96c90a3141a6056c8cdeadf983f353b154aa21fcd9c9e788dcd795e4a092094f86a5000000000000000000000000000000000000000000000000000000000000000008c4f5775d796503e96137f77c68a829a0056ac8ded70140b081b094490c57bff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ddd5d6aebcb454c1945fb52e98e5e72f6525499eda02c6243e78fe00b8da1d250000000000000000000000000000000000000000000000000000000000000000f5be8b645ab7fe71df1ba5d298ba753448988a54508957d84e8504fe86d472c01cf01534a01636c1d470708669af29c16014c935498295aade4f360c0d04d6ff00000100220000008461863bb7ece31f64c8e9b77fd31cad000300000001010000000000000000000300";

    const PCK_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIEjDCCBDKgAwIBAgIVALonBDd14S/1zfdU+ZtfOsI+ngLVMAoGCCqGSM49BAMC
MHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQK
DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV
BAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xOTA5MDUwNzQ3MDZaFw0yNjA5MDUwNzQ3
MDZaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNV
BAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkG
A1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
ZbnHpHbJ8kqQgySEX0M+qzcWpLAj6RcLi7vYKWqtityqaCWciAXHxlJvCJ1Kr35Y
mWlpekwiEjo+XlEmg+NQVKOCAqYwggKiMB8GA1UdIwQYMBaAFJ8Gl+9TIUTU+kx+
6LqNs9Ml5JKQMGsGA1UdHwRkMGIwYKBeoFyGWmh0dHBzOi8vZmFrZS1jcmwtZGlz
dHJpYnV0aW9uLXBvaW50LXVybC5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24v
djIvcGNrY3JsP2NhPXByb2Nlc3NvcjAdBgNVHQ4EFgQUEULjJXxk96LC2FJd13qm
5pKzckEwDgYDVR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwggHTBgkqhkiG+E0B
DQEEggHEMIIBwDAeBgoqhkiG+E0BDQEBBBCEYYY7t+zjH2TI6bd/0xytMIIBYwYK
KoZIhvhNAQ0BAjCCAVMwEAYLKoZIhvhNAQ0BAgECAQAwEAYLKoZIhvhNAQ0BAgIC
AQMwEAYLKoZIhvhNAQ0BAgMCAQAwEAYLKoZIhvhNAQ0BAgQCAQAwEAYLKoZIhvhN
AQ0BAgUCAQAwEAYLKoZIhvhNAQ0BAgYCAQEwEAYLKoZIhvhNAQ0BAgcCAQEwEAYL
KoZIhvhNAQ0BAggCAQAwEAYLKoZIhvhNAQ0BAgkCAQAwEAYLKoZIhvhNAQ0BAgoC
AQAwEAYLKoZIhvhNAQ0BAgsCAQAwEAYLKoZIhvhNAQ0BAgwCAQAwEAYLKoZIhvhN
AQ0BAg0CAQAwEAYLKoZIhvhNAQ0BAg4CAQAwEAYLKoZIhvhNAQ0BAg8CAQAwEAYL
KoZIhvhNAQ0BAhACAQAwEAYLKoZIhvhNAQ0BAhECAQMwHwYLKoZIhvhNAQ0BAhIE
EAADAAAAAQEAAAAAAAAAAAAwEAYKKoZIhvhNAQ0BAwQCAAAwFAYKKoZIhvhNAQ0B
BAQGAHB/AAAAMA8GCiqGSIb4TQENAQUKAQAwCgYIKoZIzj0EAwIDSAAwRQIhANmr
mwJgah3SFMDCv7/JvCW8GsB0fIuhbHQtXRO0KN0WAiAsAY5USoy5uk0B7/sVEvng
ILOJfSqEZlN7hTCJpjcEgw==
-----END CERTIFICATE-----";

    const PCK_CRL: &str = "-----BEGIN X509 CRL-----
MIIBYjCCAQgCAQEwCgYIKoZIzj0EAwIwcTEjMCEGA1UEAwwaSW50ZWwgU0dYIFBD
SyBQcm9jZXNzb3IgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYD
VQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTFw0xOTA5
MDUwNzQ3MDdaFw0yOTA5MDUwNzQ3MDdaMDUwMwIUHSENTnPXgU80wJfvSW08T6mC
aEwXDTE5MDkwNTA3NDcwN1owDDAKBgNVHRUEAwoBAaAvMC0wCgYDVR0UBAMCAQEw
HwYDVR0jBBgwFoAUnwaX71MhRNT6TH7ouo2z0yXkkpAwCgYIKoZIzj0EAwIDSAAw
RQIgdrMOjO2zTokAe2UuGCrPv7vdvPnMA/7NQ9REFCzJ9QECIQCy/o6GFcVVv0VS
c0qfH0CP94/tb0VbtD12ul2J1gKjsg==
-----END X509 CRL-----";

    const TCB_INFO: &str = r#"{"tcbInfo":{"version":2,"issueDate":"2019-09-05T07:47:07Z","nextUpdate":"2029-09-05T07:47:07Z","fmspc":"00707F000000","pceId":"0000","tcbType":0,"tcbEvaluationDataNumber":3,"tcbLevels":[{"tcb":{"sgxtcbcomp01svn":0,"sgxtcbcomp02svn":3,"sgxtcbcomp03svn":0,"sgxtcbcomp04svn":0,"sgxtcbcomp05svn":0,"sgxtcbcomp06svn":1,"sgxtcbcomp07svn":1,"sgxtcbcomp08svn":0,"sgxtcbcomp09svn":0,"sgxtcbcomp10svn":0,"sgxtcbcomp11svn":0,"sgxtcbcomp12svn":0,"sgxtcbcomp13svn":0,"sgxtcbcomp14svn":0,"sgxtcbcomp15svn":0,"sgxtcbcomp16svn":0,"pcesvn":3},"tcbDate":"2019-09-01T00:00:00Z","tcbStatus":"UpToDate"},{"tcb":{"sgxtcbcomp01svn":0,"sgxtcbcomp02svn":3,"sgxtcbcomp03svn":0,"sgxtcbcomp04svn":0,"sgxtcbcomp05svn":0,"sgxtcbcomp06svn":1,"sgxtcbcomp07svn":0,"sgxtcbcomp08svn":0,"sgxtcbcomp09svn":0,"sgxtcbcomp10svn":0,"sgxtcbcomp11svn":0,"sgxtcbcomp12svn":0,"sgxtcbcomp13svn":0,"sgxtcbcomp14svn":0,"sgxtcbcomp15svn":0,"sgxtcbcomp16svn":0,"pcesvn":3},"tcbDate":"2019-09-01T00:00:00Z","tcbStatus":"ConfigurationNeeded"},{"tcb":{"sgxtcbcomp01svn":0,"sgxtcbcomp02svn":2,"sgxtcbcomp03svn":0,"sgxtcbcomp04svn":0,"sgxtcbcomp05svn":0,"sgxtcbcomp06svn":1,"sgxtcbcomp07svn":1,"sgxtcbcomp08svn":0,"sgxtcbcomp09svn":0,"sgxtcbcomp10svn":0,"sgxtcbcomp11svn":0,"sgxtcbcomp12svn":0,"sgxtcbcomp13svn":0,"sgxtcbcomp14svn":0,"sgxtcbcomp15svn":0,"sgxtcbcomp16svn":0,"pcesvn":2},"tcbDate":"2018-08-01T00:00:00Z","tcbStatus":"OutOfDate"},{"tcb":{"sgxtcbcomp01svn":0,"sgxtcbcomp02svn":2,"sgxtcbcomp03svn":0,"sgxtcbcomp04svn":0,"sgxtcbcomp05svn":0,"sgxtcbcomp06svn":1,"sgxtcbcomp07svn":0,"sgxtcbcomp08svn":0,"sgxtcbcomp09svn":0,"sgxtcbcomp10svn":0,"sgxtcbcomp11svn":0,"sgxtcbcomp12svn":0,"sgxtcbcomp13svn":0,"sgxtcbcomp14svn":0,"sgxtcbcomp15svn":0,"sgxtcbcomp16svn":0,"pcesvn":2},"tcbDate":"2018-08-01T00:00:00Z","tcbStatus":"OutOfDateConfigurationNeeded"},{"tcb":{"sgxtcbcomp01svn":0,"sgxtcbcomp02svn":1,"sgxtcbcomp03svn":0,"sgxtcbcomp04svn":0,"sgxtcbcomp05svn":0,"sgxtcbcomp06svn":1,"sgxtcbcomp07svn":0,"sgxtcbcomp08svn":0,"sgxtcbcomp09svn":0,"sgxtcbcomp10svn":0,"sgxtcbcomp11svn":0,"sgxtcbcomp12svn":0,"sgxtcbcomp13svn":0,"sgxtcbcomp14svn":0,"sgxtcbcomp15svn":0,"sgxtcbcomp16svn":0,"pcesvn":1},"tcbDate":"2017-06-01T00:00:00Z","tcbStatus":"Revoked"},{"tcb":{"sgxtcbcomp01svn":0,"sgxtcbcomp02svn":0,"sgxtcbcomp03svn":0,"sgxtcbcomp04svn":0,"sgxtcbcomp05svn":0,"sgxtcbcomp06svn":0,"sgxtcbcomp07svn":0,"sgxtcbcomp08svn":0,"sgxtcbcomp09svn":0,"sgxtcbcomp10svn":0,"sgxtcbcomp11svn":0,"sgxtcbcomp12svn":0,"sgxtcbcomp13svn":0,"sgxtcbcomp14svn":0,"sgxtcbcomp15svn":0,"sgxtcbcomp16svn":0,"pcesvn":0},"tcbDate":"2016-10-01T00:00:00Z","tcbStatus":"OutOfDate"}]},"signature":"220d445985dcbd3407ed0d4788868b32f1c19395e63cad5d7a23b5e473c2b2ca823e04de08a1d6e6fba05ca66a62a618f06099f1532631688780dc2f2b4ce727"}"#;
    const QE_IDENTITY: &str = r#"{"enclaveIdentity":{"id":"QE","version":2,"issueDate":"2019-09-05T07:47:08Z","nextUpdate":"2029-09-05T07:47:08Z","tcbEvaluationDataNumber":0,"miscselect":"D182B18C","miscselectMask":"FFFFFFFF","attributes":"70C8CBF48BD76EAB9C8126CE95E96C90","attributesMask":"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF","mrsigner":"8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF","isvprodid":1,"tcbLevels":[{"tcb":{"isvsvn":1},"tcbDate":"2019-09-01T00:00:00Z","tcbStatus":"UpToDate"}]},"signature":"336754e3ae885d1e2cb25087b4f0fb053a5f576c7801020ff53b61b61fed3c9973a2f100b640b615d44d79ccdfa2d71bf36dc8047cbc53b0e1f2e3371f6dceae"}"#;
}
