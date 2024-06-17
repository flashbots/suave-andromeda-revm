// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.8;

contract Andromeda {
    address public constant ATTEST_ADDR        = 0x0000000000000000000000000000000000040700;
    address public constant VOLATILESET_ADDR   = 0x0000000000000000000000000000000000040701;
    address public constant VOLATILEGET_ADDR   = 0x0000000000000000000000000000000000040702;
    address public constant RANDOM_ADDR        = 0x0000000000000000000000000000000000040703;
    address public constant TDX_DCAP_VERIFY    = 0x0000000000000000000000000000000000040800;
    address public constant SHA512_ADDR        = 0x0000000000000000000000000000000000050700;
    address public constant DO_HTTP_REQUEST    = 0x0000000000000000000000000000000043200002;
    address public constant X509_GENERATE_ADDR = 0x0000000000000000000000000000000000070700;

    function volatileSet(bytes32 key, bytes32 value) public view {
        bytes memory cdata = abi.encodePacked([key, value]);
        (bool success, bytes memory _out) = VOLATILESET_ADDR.staticcall(cdata);
        _out;
        require(success);
    }

    function volatileGet(bytes32 key) public view returns (bytes32) {
        (bool success, bytes memory value) = VOLATILEGET_ADDR.staticcall(abi.encodePacked((key)));
        require(success);
        require(value.length == 32);
        return abi.decode(value, (bytes32));
    }

    function attestSgx(bytes memory userdata) public view returns (bytes memory) {
        (bool success, bytes memory attestBytes) = ATTEST_ADDR.staticcall(userdata);
        require(success);
        return attestBytes;
    }

    function localRandom() payable public returns (bytes32) {
        (bool success, bytes memory randomBytes) = RANDOM_ADDR.staticcall("");
        require(success);
        require(randomBytes.length == 32);
        return bytes32(randomBytes);
    }

    function verifyTDXDCAPQuote(bytes memory quote, string memory pckCertPem, string memory pckCrlPem, string memory tcbInfoJson, string memory qeIdentityJson) external returns (uint) {
        (bool success, bytes memory status) = TDX_DCAP_VERIFY.staticcall("");
        require(success);
        return abi.decode(status, (uint));
    }

    function sha512(bytes memory data) public view returns (bytes memory) {
        (bool success, bytes memory digest) = SHA512_ADDR.staticcall(data);
        require(success);
        require(digest.length == 64);
        return digest;
    }

    // from suave-std
    struct HttpRequest {
        string url;
        string method;
        string[] headers;
        bytes body;
        bool withFlashbotsSignature;
    }

    function doHTTPRequest(HttpRequest memory request) public returns (bytes memory) {
        (bool success, bytes memory data) = DO_HTTP_REQUEST.call(abi.encode(request));
        require(success);
        return abi.decode(data, (bytes));
    }

    function generateX509(uint256 sk) external view returns (bytes memory) {
        require(Secp256r1.isScalar(sk));
        Secp256r1.Point memory pk = Secp256r1.publicKey(sk);
        bytes memory pkcs8 = Secp256r1.encodePkcs8Der(sk, pk);
        (bool success, bytes memory data) = X509_GENERATE_ADDR.staticcall(abi.encode(pkcs8, "example.com", "example.com"));
        require(success);
        return abi.decode(data, (bytes));
    }
}

// from andromeda-sirrah-contracts
library Secp256r1 {
    address internal constant ECMUL_ADDR = 0x0000000000000000000000000000000000060700;
    uint256 internal constant ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
    uint256 internal constant G_X = 0x6b17d1f2_e12c4247_f8bce6e5_63a440f2_77037d81_2deb33a0_f4a13945_d898c296;
    uint256 internal constant G_Y = 0x4fe342e2_fe1a7f9b_8ee7eb4a_7c0f9e16_2bce3357_6b315ece_cbb64068_37bf51f5;

    struct Point {
        uint256 x;
        uint256 y;
    }

    function isScalar(uint256 scalar) internal pure returns (bool) {
        return scalar > 0 && scalar < ORDER;
    }

    function publicKey(uint256 sk) internal view returns (Point memory) {
        return ecmul(G_X, G_Y, sk);
    }

    function encodePkcs8Der(uint256 sk, Point memory pk) internal pure returns (bytes memory) {
        return bytes.concat(
            hex"308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420",
            bytes32(sk),
            hex"a14403420004",
            bytes32(pk.x),
            bytes32(pk.y)
        );
    }

    function ecmul(uint256 x, uint256 y, uint256 s) internal view returns (Point memory) {
        (bool success, bytes memory result) = ECMUL_ADDR.staticcall(abi.encode(x, y, s));
        require(success);
        return abi.decode(result, (Point));
    }
}
