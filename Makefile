.PHONY: contracts
contracts:
	forge build --revert-strings debug -C src/external_services --extra-output-files abi --out src/out
	forge build --revert-strings debug -C src/precompiles --extra-output-files abi --out src/out
	forge build --revert-strings debug -C examples/ --extra-output-files abi --out src/out

.PHONY: build
build:
	cargo build

.PHONY: examples
examples: contracts build
	cargo run -p suave-andromeda-revm --example andromeda_test

all-tests: contracts
	cargo build --features all
	cargo run -p suave-andromeda-revm --example andromeda_test --features all
	cargo test --features all

.PHONY: redis
redis:
	docker run --name services-manager-redis --rm -p 6379:6379 redis:alpine
