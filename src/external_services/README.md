# External Untrusted Services Manager

Module containing:
* Interfaces for external services (Solidity): [redis](redis/Redis.sol) and [eth builder](builder/Builder.sol)
* Sample implementations for the external services (non-obligatory!): [redis](redis/redis.rs) and [eth builder](builder/builder.rs)
* [Interface](services_manager/ServicesManager.sol) and [precompile](services_manager/ServicesManager.sol) for `ServicesManager`, which is used to access external services from Solidity contracts
* Implementation of the [services manager backend](bin/services_manager.rs)


This package is somewhat external to the parent repository. It can be made into a separate crate/module later on as needed.
