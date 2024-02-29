pragma solidity ^0.8.8;

import "./RPC.sol";

// Drop-in replacement of Suave library to use with Andromeda. Simply link this library instead of the Rigil one.
library Suave {
    error PeekerReverted(address, bytes);

    enum CryptoSignature {
        SECP256,
        BLS
    }

    type DataId is bytes16;

    struct BuildBlockArgs {
        uint64 slot;
        bytes proposerPubkey;
        bytes32 parent;
        uint64 timestamp;
        address feeRecipient;
        uint64 gasLimit;
        bytes32 random;
        Withdrawal[] withdrawals;
        bytes extra;
        bytes32 beaconRoot;
        bool fillPending;
    }

    struct DataRecord {
        DataId id;
        DataId salt;
        uint64 decryptionCondition;
        address[] allowedPeekers;
        address[] allowedStores;
        string version;
    }

    struct HttpRequest {
        string url;
        string method;
        string[] headers;
        bytes body;
        bool withFlashbotsSignature;
    }

    struct SimulateTransactionResult {
        uint64 egp;
        SimulatedLog[] logs;
        bool success;
        string error;
    }

    struct SimulatedLog {
        bytes data;
        address addr;
        bytes32[] topics;
    }

    struct Withdrawal {
        uint64 index;
        uint64 validator;
        address Address;
        uint64 amount;
    }

    address public constant ANYALLOWED = 0xC8df3686b4Afb2BB53e60EAe97EF043FE03Fb829;

    address public constant IS_CONFIDENTIAL_ADDR = 0x0000000000000000000000000000000042010000;

    address public constant BUILD_ETH_BLOCK = 0x0000000000000000000000000000000042100001;

    address public constant CONFIDENTIAL_INPUTS = 0x0000000000000000000000000000000042010001;

    address public constant CONFIDENTIAL_RETRIEVE = 0x0000000000000000000000000000000042020001;

    address public constant CONFIDENTIAL_STORE = 0x0000000000000000000000000000000042020000;

    address public constant CONTEXT_GET = 0x0000000000000000000000000000000053300003;

    address public constant DO_HTTPREQUEST = 0x0000000000000000000000000000000043200002;

    address public constant ETHCALL = 0x0000000000000000000000000000000042100003;

    address public constant EXTRACT_HINT = 0x0000000000000000000000000000000042100037;

    address public constant FETCH_DATA_RECORDS = 0x0000000000000000000000000000000042030001;

    address public constant FILL_MEV_SHARE_BUNDLE = 0x0000000000000000000000000000000043200001;

    address public constant NEW_BUILDER = 0x0000000000000000000000000000000053200001;

    address public constant NEW_DATA_RECORD = 0x0000000000000000000000000000000042030000;

    address public constant PRIVATE_KEY_GEN = 0x0000000000000000000000000000000053200003;

    address public constant SIGN_ETH_TRANSACTION = 0x0000000000000000000000000000000040100001;

    address public constant SIGN_MESSAGE = 0x0000000000000000000000000000000040100003;

    address public constant SIMULATE_BUNDLE = 0x0000000000000000000000000000000042100000;

    address public constant SIMULATE_TRANSACTION = 0x0000000000000000000000000000000053200002;

    address public constant SUBMIT_BUNDLE_JSON_RPC = 0x0000000000000000000000000000000043000001;

    address public constant SUBMIT_ETH_BLOCK_TO_RELAY = 0x0000000000000000000000000000000042100002;

    // Returns whether execution is off- or on-chain
    function isConfidential() internal returns (bool b) {
        return abi.decode(_call(IS_CONFIDENTIAL_ADDR, ""), (bool));
    }

    function buildEthBlock(BuildBlockArgs memory blockArgs, DataId dataId, string memory namespace)
        internal
        returns (bytes memory, bytes memory)
    {
        return abi.decode(_call(BUILD_ETH_BLOCK, abi.encode(blockArgs, dataId, namespace)), (bytes, bytes));
    }

    function confidentialInputs() pure internal returns (bytes memory) {
        // We are only servicig eth_calls, no confidential inputs are available in this context (on both sides)
        revert PeekerReverted(CONFIDENTIAL_INPUTS, "not available in Andromeda context");
    }

    function confidentialRetrieve(DataId dataId, string memory key) internal returns (bytes memory) {
        // Please use Andromeda's primitives instead
        return abi.decode(_call(CONFIDENTIAL_RETRIEVE, abi.encode(dataId, key)), (bytes));
    }

    function confidentialStore(DataId dataId, string memory key, bytes memory value) internal {
        // Please use Andromeda's primitives instead
        _call(CONFIDENTIAL_STORE, abi.encode(dataId, key, value));
    }

    function contextGet(string memory key) internal returns (bytes memory) {
        // Please use Andromeda's primitives instead
        return abi.decode(_call(CONTEXT_GET, abi.encode(key)), (bytes));
    }

    function doHTTPRequest(HttpRequest memory request) internal returns (bytes memory) {
        // TODO: should be moved to a native revm precompile
        return abi.decode(_call(DO_HTTPREQUEST, abi.encode(request)), (bytes));
    }

    function ethcall(address contractAddr, bytes memory input1) internal returns (bytes memory) {
        return abi.decode(_call(ETHCALL, abi.encode(contractAddr, input1)), (bytes));
    }

    function extractHint(bytes memory bundleData) internal returns (bytes memory) {
        return abi.decode(_call(EXTRACT_HINT, abi.encode(bundleData)), (bytes));
    }

    function fetchDataRecords(uint64 cond, string memory namespace) internal returns (DataRecord[] memory) {
        // Please use Andromeda's primitives instead
        return abi.decode(_call(FETCH_DATA_RECORDS, abi.encode(cond, namespace)), (DataRecord[]));
    }

    function fillMevShareBundle(DataId dataId) internal returns (bytes memory) {
        return abi.decode(_call(FILL_MEV_SHARE_BUNDLE, abi.encode(dataId)), (bytes));
    }

    function newBuilder() internal returns (string memory) {
        return abi.decode(_call(NEW_BUILDER, abi.encode()), (string));
    }

    function newDataRecord(
        uint64 decryptionCondition,
        address[] memory allowedPeekers,
        address[] memory allowedStores,
        string memory dataType
    ) internal returns (DataRecord memory) {
        return abi.decode(_call(NEW_DATA_RECORD, abi.encode(decryptionCondition, allowedPeekers, allowedStores, dataType)), (DataRecord));
    }

    function privateKeyGen(CryptoSignature crypto) internal returns (string memory) {
        // Please use Andromeda's primitives instead
        return abi.decode(_call(PRIVATE_KEY_GEN, abi.encode(crypto)), (string));
    }

    function signEthTransaction(bytes memory txn, string memory chainId, string memory signingKey)
        internal
        returns (bytes memory)
    {
        return abi.decode(_call(SIGN_ETH_TRANSACTION, abi.encode(txn, chainId, signingKey)), (bytes));
    }

    function signMessage(bytes memory digest, CryptoSignature crypto, string memory signingKey)
        internal
        returns (bytes memory)
    {
        return abi.decode(_call(SIGN_MESSAGE, abi.encode(digest, crypto, signingKey)), (bytes));
    }

    function simulateBundle(bytes memory bundleData) internal returns (uint64) {
        return abi.decode(_call(SIMULATE_BUNDLE, abi.encode(bundleData)), (uint64));
    }

    function simulateTransaction(string memory sessionid, bytes memory txn)
        internal
        returns (SimulateTransactionResult memory)
    {
        return abi.decode(_call(SIMULATE_TRANSACTION, abi.encode(sessionid, txn)), (SimulateTransactionResult));
    }

    function submitBundleJsonRPC(string memory url, string memory method, bytes memory params)
        internal
        returns (bytes memory)
    {
        return abi.decode(_call(SUBMIT_BUNDLE_JSON_RPC, abi.encode(url, method, params)), (bytes));
    }

    function submitEthBlockToRelay(string memory relayUrl, bytes memory builderBid) internal returns (bytes memory) {
        return abi.decode(_call(SUBMIT_ETH_BLOCK_TO_RELAY, abi.encode(relayUrl, builderBid)), (bytes));
    }

    // Glue code for the service handle
    uint256 public constant RIGIL_CHAINID = 16813125;

    struct HandleStorage {
        bytes32 _volatile_handle;
    }

    function _handle() internal returns (bytes32) {
        bytes32 pos = keccak256("handle.storage");
        HandleStorage storage hs;
        assembly { hs.slot := pos }

        if (hs._volatile_handle == bytes32(0x0)) {
            bytes memory config = abi.encode(BlockchainRPC.Config(RIGIL_CHAINID));
            (bool s_ok, bytes memory s_data) = SM_ADDR.staticcall(abi.encodeWithSelector(SM.getService.selector, "blockchain_rpc", config));
            require(s_ok, string(abi.encodePacked("getService for rigil rpc failed: ", string(s_data))));
            (bytes32 handle, bytes memory err) = abi.decode(s_data, (bytes32, bytes));
            require(err.length == 0, string(abi.encodePacked("could not initialize rigil rpc: ", string(err))));
            hs._volatile_handle = handle;
        }

        return hs._volatile_handle;
    }

    function _call(address precompile, bytes memory input) internal returns (bytes memory) {
        bytes memory eth_call_data = abi.encodeWithSelector(BlockchainRPC.eth_call.selector, precompile, input);
        (bool c_ok, bytes memory c_data) = SM_ADDR.staticcall(abi.encodeWithSelector(SM.callService.selector, _handle(), eth_call_data));
        require(c_ok, string(abi.encodePacked("rigil rpc call failed: ", string(c_data))));
        return c_data;
    }
}
