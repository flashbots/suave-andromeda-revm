pragma solidity ^0.8.19;

import "../services_manager/ServicesManager.sol";

interface RedisPubsub {
    function publish(string memory topic, bytes memory msg) external;
    function get_message(string memory topic) external returns (bytes memory);

    function subscribe(string memory topic) external;
    function unsubscribe(string memory topic) external;
}

contract WithRedisPubsub {
    ExternalServiceImpl private impl;
    constructor() {
        bytes memory config;
        impl = new ExternalServiceImpl("pubsub", config);
    }

    function pubsub() internal view returns (RedisPubsub) {
        return RedisPubsub(address(impl));
    }
}
