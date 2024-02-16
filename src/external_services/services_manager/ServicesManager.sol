pragma solidity ^0.8.19;

address constant SM_ADDR = address(0x3507); // Can be a library, a precompile, or a contract

interface SM {
    function getService(string memory service_name, bytes memory config) external returns (bytes32 handle, bytes memory err);
    function callService(bytes32 handle, bytes memory cdata) external returns (bytes memory);

    /* context is supplemented by the precompile! */
    struct Context {
        uint256 blockNumber;
        address origin;
        address caller;
    }
    function callServiceWithContext(Context memory env, bytes32 handle, bytes memory cdata) external returns (bytes memory);
}

contract ExternalServiceImpl {
    string private service;
    bytes private config;
    constructor(string memory _service, bytes memory _config) {
        service = _service;
        config = _config;
        _volatile_handle = bytes32(0x0);
    }

    bytes32 private _volatile_handle; /* Only kept for a single mevm context */
    fallback(bytes calldata cdata) external returns (bytes memory) {
        if (_volatile_handle == bytes32(0x0)) {
            (bool s_ok, bytes memory s_data) = SM_ADDR.staticcall(abi.encodeWithSelector(SM.getService.selector, service, config));
            require(s_ok, string(abi.encodePacked("getService for ", service, " failed: ", string(s_data))));
            (bytes32 handle, bytes memory err) = abi.decode(s_data, (bytes32, bytes));
            require(err.length == 0, string(abi.encodePacked("could not initialize ", service, ": ", string(err))));
            _volatile_handle = handle;
        }

        (bool c_ok, bytes memory c_data) = SM_ADDR.staticcall(abi.encodeWithSelector(SM.callService.selector, _volatile_handle, cdata));
        require(c_ok, string(abi.encodePacked(service, " call failed: ", string(c_data))));
        return c_data;
    }
}
