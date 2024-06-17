pragma solidity ^0.8.19;

interface TDX_DCAP {
    function verifyQuote(bytes memory quote, string memory pckCertPem, string memory pckCrlPem, string memory tcbInfoJson, string memory qeIdentityJson) external returns (uint status);
    /*
       TODO: also add the following
    pub fn sgxAttestationVerifyPCKCertificate(
        pemCertChain: *const ::std::os::raw::c_char,
        crls: *const *const ::std::os::raw::c_char,
        pemRootCaCertificate: *const ::std::os::raw::c_char,
        expirationCheckDate: *const time_t,
    ) -> Status;
    pub fn sgxAttestationVerifyPCKRevocationList(
        crl: *const ::std::os::raw::c_char,
        pemCACertChain: *const ::std::os::raw::c_char,
        pemTrustedRootCaCert: *const ::std::os::raw::c_char,
    ) -> Status;
    pub fn sgxAttestationVerifyEnclaveIdentity(
        enclaveIdentityString: *const ::std::os::raw::c_char,
        pemCertChain: *const ::std::os::raw::c_char,
        rootCaCrl: *const ::std::os::raw::c_char,
        pemRootCaCertificate: *const ::std::os::raw::c_char,
        expirationCheckDate: *const time_t,
    ) -> Status;
    pub fn sgxAttestationVerifyTCBInfo(
        tcbInfo: *const ::std::os::raw::c_char,
        pemCertChain: *const ::std::os::raw::c_char,
        rootCaCrl: *const ::std::os::raw::c_char,
        pemRootCaCertificate: *const ::std::os::raw::c_char,
        expirationCheckDate: *const time_t,
    ) -> Status;
     */
}
