use revm::precompile::PrecompileWithAddress;

use crate::precompiles::hash;
use crate::precompiles::http;
use crate::precompiles::p256;
use crate::precompiles::services_manager;
use crate::precompiles::sgxattest;
use crate::precompiles::x509;

#[cfg(feature = "tdx_dcap")]
use crate::precompiles::tdx_dcap;

pub fn andromeda_precompiles() -> impl IntoIterator<Item = PrecompileWithAddress> {
    [
        services_manager::RUN,
        sgxattest::ATTEST,
        sgxattest::VOLATILESET,
        sgxattest::VOLATILEGET,
        sgxattest::RANDOM,
        sgxattest::SEALINGKEY,
        #[cfg(feature = "tdx_dcap")]
        tdx_dcap::VERIFY_QUOTE,
        hash::SHA512,
        http::HTTP_CALL,
        x509::GENERATE_CERTIFICATE,
        p256::ECMUL,
    ]
}
