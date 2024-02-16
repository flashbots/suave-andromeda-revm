pragma solidity ^0.8.19;

import "../services_manager/ServicesManager.sol";

interface Redis {
    function set(string memory key, bytes memory value) external;
    function get(string memory key) external returns (bytes memory);
}

contract WithRedis {
    ExternalServiceImpl private impl;
    constructor() {
        bytes memory config;
        impl = new ExternalServiceImpl("redis", config);
    }

    function redis() internal view returns (Redis) {
        return Redis(address(impl));
    }
}

contract RedisImpl is ExternalServiceImpl {
    constructor() ExternalServiceImpl("redis", "") {}
}
