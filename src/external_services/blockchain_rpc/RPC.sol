pragma solidity ^0.8.19;

import "../services_manager/ServicesManager.sol";

interface BlockchainRPC {
    struct Config {
        uint256 chainId; // The kettle operator provides the url, we can only specify for which chain!
    }

    function raw_jsonrpc(string memory method, bytes[] memory params) external returns (bytes memory result);
    function eth_call(address to, bytes memory input) external returns (bytes memory result);
}

contract WithBlockchainRPC {
    ExternalServiceImpl private impl;
    constructor(uint256 chainId) {
        bytes memory config = abi.encode(BlockchainRPC.Config(chainId));
        impl = new ExternalServiceImpl("blockchain_rpc", config);
    }

    function rpc() internal view returns (BlockchainRPC) {
        return BlockchainRPC(address(impl));
    }
}

// Wraps an arbitrary interface to a contract on a different chain
contract EthCallWrapper is WithBlockchainRPC {
    address wrappedContract;

    constructor(uint256 chainId, address _wrappedContract) WithBlockchainRPC(chainId) {
        wrappedContract = _wrappedContract;
    }

    fallback(bytes calldata cdata) external returns (bytes memory) {
        return rpc().eth_call(wrappedContract, cdata);
    }
}
