> [!WARNING]
> This repository is a work in progress, and for now only functions as a showcase. This code *is not intended to secure any valuable information*.

# Anrdomeda REVM

This an EVM with precompiles used internally by SUAVE for key management and boostrapping kettles.

## How the Andromeda precompiles work

The Andromeda [precompiles](src/precompiles/) rely on features from Gramine, provided through the filesystem. The gramine environment is [provided separately](https://github.com/flashbots/gramine-andromeda-revm). Running the examples and tests here just run locally, approximating this.

- `Suave.localRandom` uses the `RDRAND` instruction [via Gramine's `/dev/urandom`](https://gramine.readthedocs.io/en/stable/devel/features.html#randomness).
- `Suave.volatile{Set/Get}` uses a simple static `HashMap` in local memory. It does not persist through a service restart.
- `Suave.attestSgx` uses [Gramine's remote attestation `/dev/attestation/quote`](https://gramine.readthedocs.io/en/stable/devel/features.html#attestation).
- `Suave.sealingKey` uses [Gramine's pseudo-directory `/dev/attestation/keys`](https://gramine.readthedocs.io/en/stable/devel/features.html#attestation) feature.
- `Suave.verifyQuote` uses [intel/SGX-TDX-DCAP-QuoteVerificationLibrary](https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/).

As additional utility precompiles we include:
- `Suave.doHTTPRequest`, which uses `/etc/ssl/ca-certificates.crt` for HTTPS certificates (the file must be included in the Gramine manifest!).

The tests include a thin wrapper for the precompiles [examples/Andromeda.sol]. This is a small interface, but it should be sufficient to run the [Key Manager demo](https://github.com/flashbots/andromeda-sirrah-contracts/)

## SUAVE chain state

The revm itself is statless - we don't keep any chain data inside. To provide chain state we have introduced a witness-based database. The database itself is defined in [remote_db.rs](src/remote_db.rs), and verifying witness is done through [helios](https://github.com/a16z/helios). For SUAVE chain's Proof of Authority we have added a simple [consensus](src/consensus.rs) checker that verifies the blocks were signed by one of the trusted block proposers (`[0x0981717712ed2c4919fdbc27dfc804800a9eeff9, 0x0e5b9aa4925ed1beeb08d1c5a92477a1b719baa7, 0x0e8705e07bbe1ce2c39093df3d20aaa5120bfc7a]`).

State is possibly fetched at two times:
* Before the execution all of the access list state is pre-fetched
* During EVM execution if a slot is missing it will be fetched from the execution client

## Stateful executor

The main service we provide in this repository is the [StatefulExecutor](src/stateful.rs). This is a service which persists volatile memory (for `Suave.volatile{Set/Get}`) and manages the SUAVE chain light client.  

There are two methods that the `StatefulExecutor` implements:
* `advance [height=latest]`, which advances the suave chain light client to the requested height
* `execute tx_env`, which executes the requested call. The `tx_env` is expected to be JSON-encoded [TxEnv](https://github.com/flashbots/revm/blob/extensible-precompiles/crates/primitives/src/env.rs#L509) structure.

## Building
```shell
make build
```

**_Note:_** `clang` is required for building revm with `c-kzg` or `secp256k1` feature flags as they depend on `C` libraries. If you don't have it installed, you can install it with `apt install clang`.

## Running example locally (no gramine)

To mock out `/dev/attestation/quote`, and `/dev/attestation/user_report_data`, just try
```shell
sudo mkdir /dev/attestation
sudo chown $USER:$USER /dev/attestation
echo "dummnyquote" > /dev/attestation/quote
```

```shell
make examples
```

## License

The code in this project is free software under the [MIT license](LICENSE).
