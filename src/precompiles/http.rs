use std::str::FromStr;

use reqwest::blocking::Client as ReqwestClient;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use ethers::abi::{decode, encode, ParamType, Token};
use revm::precompile::{
    Precompile, PrecompileError, PrecompileResult, PrecompileWithAddress, StandardPrecompileFn,
};

use crate::u64_to_address;

pub const HTTP_CALL: PrecompileWithAddress = PrecompileWithAddress::new(
    u64_to_address(0x43200002),
    Precompile::Standard(httpcall as StandardPrecompileFn),
);

const HTTP_CANNOT_REQUEST: PrecompileError =
    PrecompileError::CustomPrecompileError("unable to perform http request");
const HTTP_CANNOT_DECODE_RESP: PrecompileError =
    PrecompileError::CustomPrecompileError("unable to decode http call response");

const HTTP_INVALID_INPUT: PrecompileError =
    PrecompileError::CustomPrecompileError("unable to abi-decode input");
const HTTP_FLASHBOTS_SIG_NOT_SUPPORTED: PrecompileError =
    PrecompileError::CustomPrecompileError("flashbots signature not allowed in http calls");
const HTTP_INVALID_URL: PrecompileError =
    PrecompileError::CustomPrecompileError("unable to abi-decode request url");
const HTTP_INVALID_METHOD: PrecompileError =
    PrecompileError::CustomPrecompileError("unable to abi-decode request method");
const HTTP_INVALID_HEADER: PrecompileError =
    PrecompileError::CustomPrecompileError("unable to abi-decode request header");
const HTTP_INVALID_DATA: PrecompileError =
    PrecompileError::CustomPrecompileError("unable to abi-decode request data");

fn httpcall(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas_used = 10000 as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    /* Decode the ABI input (url, method, body)
     * struct HttpRequest {
     *   string url;
     *   string method;
     *   string[] headers;
     *   bytes body;
     *   bool withFlashbotsSignature
     * } */
    let decoded = decode(
        &[ParamType::Tuple(vec![
            ParamType::String,
            ParamType::String,
            ParamType::Array(Box::new(ParamType::String)),
            ParamType::Bytes,
            ParamType::Bool,
        ])],
        input,
    )
    .map_err(|_e| {
        println!("{:?}", _e);
        HTTP_INVALID_INPUT
    })?;

    let input_tuple_raw = decoded[0]
        .to_owned()
        .into_tuple()
        .ok_or(HTTP_INVALID_INPUT)?;
    let input_tuple = input_tuple_raw.as_slice();

    if input_tuple[4]
        .to_owned()
        .into_bool()
        .ok_or(HTTP_INVALID_INPUT)?
    {
        return Err(HTTP_FLASHBOTS_SIG_NOT_SUPPORTED);
    }

    let url = input_tuple[0]
        .to_owned()
        .into_string()
        .ok_or(HTTP_INVALID_URL)?;

    let method = input_tuple[1]
        .to_owned()
        .into_string()
        .ok_or(HTTP_INVALID_METHOD)?
        .to_lowercase();

    if method != "get" && method != "post" {
        return Err(HTTP_INVALID_METHOD);
    }

    let req_data = input_tuple[3]
        .to_owned()
        .into_bytes()
        .ok_or(HTTP_INVALID_DATA)?;

    if method == "get" && req_data.len() != 0 {
        return Err(HTTP_INVALID_DATA);
    }

    let headers_data = input_tuple[2]
        .to_owned()
        .into_array()
        .ok_or(HTTP_INVALID_HEADER)?;

    let mut headers = HeaderMap::new();
    for raw_header_data in headers_data {
        let raw_header_string = raw_header_data.into_string().ok_or(HTTP_INVALID_HEADER)?;
        let (key, value) = raw_header_string
            .split_once(":")
            .ok_or(HTTP_INVALID_HEADER)?;

        headers.append(
            HeaderName::from_str(key.trim()).map_err(|_e| HTTP_INVALID_HEADER)?,
            HeaderValue::from_str(value.trim()).map_err(|_e| HTTP_INVALID_HEADER)?,
        );
    }

    // Perform the HTTP call
    let client = ReqwestClient::new();
    let response = (|| match method.as_str() {
        "get" => client.get(url).headers(headers).send().map_err(|_e| {
            println!("{:?}", _e);
            HTTP_CANNOT_REQUEST
        }),
        "post" => client
            .post(url)
            .headers(headers)
            .body(req_data)
            .send()
            .map_err(|_e| {
                println!("{:?}", _e);
                HTTP_CANNOT_REQUEST
            }),
        _ => Err(HTTP_INVALID_METHOD),
    })()?;

    let response_body = response.bytes().map_err(|_e| {
        println!("{:?}", _e);
        HTTP_CANNOT_DECODE_RESP
    })?;

    // ABI-encode the response
    let encoded_response = encode(&[Token::Bytes(response_body.to_vec())]);

    Ok((gas_used, encoded_response))
}

#[cfg(test)]
mod tests {
    use httptest::{matchers::*, responders::*, Expectation, Server};

    use super::*;

    #[test]
    fn http_call() -> Result<(), String> {
        let mut server = Server::run();

        {
            // Green path - post with a body and headers
            server.expect(
                Expectation::matching(httptest::matchers::all_of(vec![
                    Box::new(request::method_path("POST", "/foo")),
                    Box::new(request::body("xoxo")),
                    Box::new(request::headers(contains(("x-xoxo", "XOXO")))),
                ]))
                .respond_with(status_code(200).body("test test test")),
            );

            let input = encode(&[Token::Tuple(vec![
                Token::String(server.url("/foo").to_string()),
                Token::String(String::from("post")),
                Token::Array(vec![Token::String(String::from("x-xoxo: XOXO"))]),
                Token::Bytes(String::from("xoxo").into_bytes()),
                Token::Bool(false),
            ])]);
            let res = httpcall(&input, 10000).expect("http call did not succeed");
            assert_eq!(
                res.1,
                encode(&[Token::Bytes(String::from("test test test").into_bytes())])
            );

            server.verify_and_clear()
        }

        {
            // Green path - get
            server.expect(
                Expectation::matching(httptest::matchers::all_of(vec![
                    Box::new(request::method_path("GET", "/foo")),
                    Box::new(request::headers(contains(("x-xoxo", "XOXO")))),
                ]))
                .respond_with(status_code(200).body("test test test")),
            );

            let input = encode(&[Token::Tuple(vec![
                Token::String(server.url("/foo").to_string()),
                Token::String(String::from("get")),
                Token::Array(vec![Token::String(String::from("x-xoxo: XOXO"))]),
                Token::Bytes(vec![]),
                Token::Bool(false),
            ])]);
            let res = httpcall(&input, 10000).expect("http call did not succeed");
            assert_eq!(
                res.1,
                encode(&[Token::Bytes(String::from("test test test").into_bytes())])
            );

            server.verify_and_clear()
        }

        {
            // Red path - get with body
            let input = encode(&[Token::Tuple(vec![
                Token::String(server.url("/foo").to_string()),
                Token::String(String::from("get")),
                Token::Array(vec![]),
                Token::Bytes(String::from("xoxo").into_bytes()),
                Token::Bool(false),
            ])]);
            assert_eq!(httpcall(&input, 10000), Err(HTTP_INVALID_DATA));
        }

        {
            // Red path - flashbots signature
            let input = encode(&[Token::Tuple(vec![
                Token::String(server.url("/foo").to_string()),
                Token::String(String::from("get")),
                Token::Array(vec![]),
                Token::Bytes(String::from("xoxo").into_bytes()),
                Token::Bool(true),
            ])]);
            assert_eq!(
                httpcall(&input, 10000),
                Err(HTTP_FLASHBOTS_SIG_NOT_SUPPORTED)
            );
        }

        Ok(())
    }
}
