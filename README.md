# Anrdomeda REVM

This an EVM with precompiles used internally by SUAVE for key management and boostrapping kettles.

## How the Andromeda precompiles work

The Andromeda [precompiles](src/precompiles/) rely on features from Gramine, provided through the filesystem. The gramine environment is [provided separately](https://github.com/flashbots/gramine-andromeda-revm). Running the examples and tests here just run locally, approximating this.

- `Suave.localRandom` uses the `RDRAND` instruction [via Gramine's `/dev/urandom`](https://gramine.readthedocs.io/en/stable/devel/features.html#randomness).
- TODO `Suave.volatile{Set/Get}` uses a data structure in local memory
- `Suave.attestSgx` uses [Gramine's remote attestation `/dev/attestation/quote`](https://gramine.readthedocs.io/en/stable/devel/features.html#attestation)

The tests include a thin wrapper for the precompiles [examples/Andromeda.sol]. This is a small interface, but it should be sufficient to run the [Key Manager demo](https://github.com/flashbots/andromeda-keymgr-contracts/)

## Building
```shell
solcjs --bin -o examples examples/Andromeda.sol
cargo build
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
cargo run -p suave-andromeda-revm --example andromeda_test
```
