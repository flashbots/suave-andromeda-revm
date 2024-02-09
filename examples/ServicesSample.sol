pragma solidity ^0.8.19;

import "../src/external_services/redis/Redis.sol";
import "../src/external_services/redis/Pubsub.sol";
import "../src/external_services/builder/Builder.sol";

uint256 constant GOERLI_CHAINID = 5;

contract StoreServiceSample is WithRedis, WithRedisPubsub, WithBuilder {
    // SM could also be a contract passed in here
    constructor() WithRedis() WithRedisPubsub() WithBuilder(GOERLI_CHAINID) {
    }

    function addBundle(Builder.Bundle memory bundle) public {
        bundle.profit = builder().simulate(bundle).profit;
        internal_addBundle(abi.encode(bundle), bundle.height);
        pubsub().publish("bundles", abi.encode(bundle));
    }

    function internal_addBundle(bytes memory bundle, uint256 height) internal {
        bytes32 bundleHash = keccak256(bundle);
        redis().set(string(abi.encodePacked("bundle-", bundleHash)), bundle);

        bytes32[] memory n_bundles;
        bytes memory c_bundles_raw = redis().get(string(abi.encodePacked("bundles-", height)));
        if (c_bundles_raw.length > 0) {
            bytes32[] memory c_bundles = abi.decode(c_bundles_raw, (bytes32[]));
            n_bundles = new bytes32[](c_bundles.length+1);
            n_bundles[c_bundles.length] = bundleHash;
            for (uint i = 0; i < c_bundles.length; i++) {
                n_bundles[i] = c_bundles[i];
            }
        } else {
            n_bundles = new bytes32[](1);
            n_bundles[0] = bundleHash;
        }

        redis().set(string(abi.encodePacked("bundles-", height)), abi.encode(n_bundles));
        
        /* Could also order by profit already too */
    }

    function getBundlesByHeight(uint256 height) public returns (bool found, Builder.Bundle[] memory bundles) {
        bytes memory c_bundles_raw = redis().get(string(abi.encodePacked("bundles-", height)));
        if (c_bundles_raw.length == 0) {
            return (false, bundles);
        }

        bytes32[] memory c_bundles = abi.decode(c_bundles_raw, (bytes32[]));
        bundles = new Builder.Bundle[](c_bundles.length);
        for (uint i = 0; i < c_bundles.length; i++) {
            bytes memory bundle_raw = redis().get(string(abi.encodePacked("bundle-", c_bundles[i])));
            if (bundle_raw.length > 0) {
                bundles[i] = abi.decode(bundle_raw, (Builder.Bundle));
            } else {
                // wat do?
            }
        }

        return (true, bundles);
    }

    function subscribeBundles() external {
        pubsub().subscribe("bundles");
    }

    function consumeMessages(uint maxMsgs) external returns (uint) {
        for (uint i = 0; i < maxMsgs; i++) {
            bytes memory raw_message = pubsub().get_message("bundles");
            if (raw_message.length == 0) {
                // queue empty
                return i;
            }

            Builder.Bundle memory bundle = abi.decode(raw_message, (Builder.Bundle));
            internal_addBundle(abi.encode(bundle), bundle.height);
        }

        return maxMsgs;
    }

    /* Test functions */
    function ping(bytes memory data) public returns (bytes memory) {
        return data;
    }

    function push_message(bytes memory data) public {
        pubsub().subscribe("test-topic");
        pubsub().publish("test-topic", data);
    }

    function get_message() public returns (bytes memory) {
        return pubsub().get_message("test-topic");
    }
    /* */

}
