use revm::{
    primitives::{address, AccountInfo, Address, Bytecode, Bytes, Env, TxEnv},
    InMemoryDB,
};

use hex::FromHex;

use alloy::{sol, sol_types::SolCall};
use ethers::abi::{encode, ethabi, parse_abi, JsonAbi, Token};
use ethers::contract::{BaseContract, Lazy};
use std::include_str;

use suave_andromeda_revm::new_andromeda_revm;

fn main() -> eyre::Result<()> {
    // Read from the untrusted host via a Gramine-mapped file
    simulate()?;
    Ok(())
}

pub static ANDROMEDA_CODE: Lazy<JsonAbi> = Lazy::new(|| {
    serde_json::from_str(include_str!("../src/out/Andromeda.sol/Andromeda.json")).unwrap()
});

pub static ADDR_A: Address = address!("4838b106fce9647bdf1e7877bf73ce8b0bad5f97");
pub static ADDR_B: Address = address!("F2d01Ee818509a9540d8324a5bA52329af27D19E");

fn simulate() -> eyre::Result<()> {
    let mut db = InMemoryDB::default();

    let info = AccountInfo {
        code: Some(Bytecode::new_raw(Bytes::from_iter(
            ANDROMEDA_CODE.deployed_bytecode().unwrap().into_iter(),
        ))),
        ..Default::default()
    };
    db.insert_account_info(ADDR_B, info);

    let env = Box::new(Env::default());
    let mut evm = new_andromeda_revm(&mut db, env);

    let abi = BaseContract::from(parse_abi(&[
        "function localRandom() returns (bytes32)",
        "function attestSgx(bytes) returns (bytes)",
        "function volatileSet(bytes32,bytes32)",
        "function volatileGet(bytes32) returns (bytes32)",
        "function verifyTDXDCAPQuote(bytes, string, string, string, string) returns (uint)",
        "function sha512(bytes) returns (bytes)",
        "struct HttpRequest { string url; string method; string[] headers; bytes body; bool withFlashbotsSignature; }",
        "function doHTTPRequest(HttpRequest memory request) returns (bytes memory)",
        "function generateX509(uint256 sk) returns (bytes memory)",
    ])?);

    //////////////////////////
    // Suave.localRandom()
    //////////////////////////
    {
        let calldata = abi.encode("localRandom", ())?;
        evm.context.evm.inner.env.tx = TxEnv {
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
        evm.context.evm.inner.env.tx = TxEnv {
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
        evm.context.evm.inner.env.tx = TxEnv {
            caller: ADDR_A,
            transact_to: revm::primitives::TransactTo::Call(ADDR_B),
            data: revm::primitives::Bytes::from(calldata.0),
            ..Default::default()
        };
        let result = evm.transact()?;
        assert!(result.result.is_success());
    }
    {
        let calldata = abi.encode("volatileGet", (Token::FixedBytes(mykey),))?;
        evm.context.evm.inner.env.tx = TxEnv {
            caller: ADDR_A,
            transact_to: revm::primitives::TransactTo::Call(ADDR_B),
            data: revm::primitives::Bytes::from(calldata.0),
            ..Default::default()
        };
        let result = evm.transact()?;
        assert!(result.result.is_success());
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

    /////////////////////////////
    // Suave.verifyTDXDCAPQuote
    /////////////////////////////
    #[cfg(feature = "tdx_dcap")]
    {
        sol!(
            #[allow(missing_docs)]
            function verifyTDXDCAPQuote(bytes memory quote, string memory pckCertPem, string memory pckCrlPem, string memory tcbInfoJson, string memory qeIdentityJson) public view returns (uint);
        );

        let call = verifyTDXDCAPQuoteCall {
            quote: Vec::from_hex(QUOTE_HEX).unwrap().into(),
            pckCertPem: PCK_CERT.to_string(),
            pckCrlPem: PCK_CRL.to_string(),
            tcbInfoJson: TCB_INFO.to_string(),
            qeIdentityJson: QE_IDENTITY.to_string(),
        };

        evm.context.evm.inner.env.tx = TxEnv {
            caller: ADDR_A,
            transact_to: revm::primitives::TransactTo::Call(ADDR_B),
            data: revm::primitives::Bytes::from(call.abi_encode()),
            ..Default::default()
        };
        let result = evm.transact()?;
        assert!(result.result.is_success());
        assert_eq!(
            result.result.into_output().unwrap(),
            encode(&[Token::Uint(0.into())])
        );
    }

    //////////////////////////
    // Suave.sha512
    //////////////////////////
    {
        let calldata = abi.encode("sha512", (Token::Bytes("test".as_bytes().to_vec()),))?;
        evm.context.evm.inner.env.tx = TxEnv {
            caller: ADDR_A,
            transact_to: revm::primitives::TransactTo::Call(ADDR_B),
            data: revm::primitives::Bytes::from(calldata.0),
            ..Default::default()
        };
        let result = evm.transact()?;
        assert!(result.result.is_success());
        let decoded = ethabi::decode(&[ethabi::ParamType::Bytes], result.result.output().unwrap())?;
        let hash = match &decoded[0] {
            Token::Bytes(b) => b,
            _ => todo!(),
        };
        let hex: String = hash.iter().map(|byte| format!("{:02x}", byte)).collect();
        dbg!(hex);
    }

    //////////////////////////
    // Suave.doHttpRequest
    //////////////////////////
    {
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let mut server = Server::run();

        server.expect(
            Expectation::matching(httptest::matchers::all_of(vec![
                Box::new(request::method_path("POST", "/foo")),
                Box::new(request::body("xoxo")),
                Box::new(request::headers(contains(("x-xoxo", "XOXO")))),
            ]))
            .respond_with(status_code(200).body("test test test")),
        );

        let calldata = abi.encode(
            "doHTTPRequest",
            (Token::Tuple(vec![
                Token::String(server.url("/foo").to_string()),
                Token::String(String::from("post")),
                Token::Array(vec![Token::String(String::from("x-xoxo: XOXO"))]),
                Token::Bytes(String::from("xoxo").into_bytes()),
                Token::Bool(false),
            ]),),
        )?;

        evm.context.evm.inner.env.tx = TxEnv {
            caller: ADDR_A,
            transact_to: revm::primitives::TransactTo::Call(ADDR_B),
            data: revm::primitives::Bytes::from(calldata.0),
            ..Default::default()
        };
        let result = evm.transact()?;
        assert!(result.result.is_success());
        let decoded = ethabi::decode(&[ethabi::ParamType::Bytes], result.result.output().unwrap())?;
        let outp = decoded[0]
            .clone()
            .into_bytes()
            .expect("invalid output encoding");
        assert_eq!(&outp, b"test test test");
        server.verify_and_clear();
    }

    {
        let calldata = abi.encode(
            "generateX509",
            (Token::Uint(
                "89ed108f0366a89aaf12be76d0136157ab5967efd30cd131fdf69d4176ea32fc".parse()?,
            ),),
        )?;

        evm.context.evm.inner.env.tx = TxEnv {
            caller: ADDR_A,
            transact_to: revm::primitives::TransactTo::Call(ADDR_B),
            data: revm::primitives::Bytes::from(calldata.0),
            ..Default::default()
        };
        let result = evm.transact()?;
        assert!(result.result.is_success());
        let decoded = ethabi::decode(
            &[ethabi::ParamType::Bytes],
            dbg!(result.result.output().unwrap()),
        )?;
        let outp = decoded[0]
            .clone()
            .into_bytes()
            .expect("invalid output encoding");
        eprintln!("certificate: {}", ethers::types::Bytes::from(outp));
    }

    Ok(())
}

// TDX example quote data
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
