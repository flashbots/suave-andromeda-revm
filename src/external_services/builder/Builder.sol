pragma solidity ^0.8.19;

import "../services_manager/ServicesManager.sol";

interface Builder {
    struct Config {
        uint256 chainId;
    }
    struct Bundle {
        uint256 height;
        bytes transaction;
        uint256 profit;
    }
    struct SimResult {
        uint256 profit;
    }
    struct Block {
        uint256 profit;
    }

    function newSession() external returns (string memory sessionId);
    function addTransaction(string memory sessionId, bytes memory tx) external returns (SimResult memory);

    function simulate(Bundle memory bundle) external returns (SimResult memory);
    function buildBlock(Bundle[] memory bundle) external returns (Block memory);
}

contract WithBuilder {
    ExternalServiceImpl private impl;

    constructor(uint256 chainId) {
        impl = new ExternalServiceImpl("builder", abi.encode(Builder.Config(chainId)));
    }

    function builder() public view returns (Builder) {
        return Builder(address(impl));
    }
}
