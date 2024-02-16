use once_cell::race::OnceBox;

use revm::precompile::Precompiles;

#[cfg(feature = "external_services")]
use crate::precompiles::services_manager;

use crate::precompiles::sgxattest;

pub fn andromeda_precompiles() -> &'static Precompiles {
    static INSTANCE: OnceBox<Precompiles> = OnceBox::new();
    INSTANCE.get_or_init(|| {
        let mut precompiles: Precompiles = Precompiles::istanbul().clone();
        // Mind that the vector must be sorted
        #[cfg(feature = "external_services")]
        precompiles
            .inner
            .extend(sm_precompiles().inner.clone().into_iter());
        precompiles
            .inner
            .extend(sgx_precompiles().inner.clone().into_iter());
        Box::new(precompiles.clone())
    })
}

pub fn sgx_precompiles() -> &'static Precompiles {
    static INSTANCE: OnceBox<Precompiles> = OnceBox::new();
    INSTANCE.get_or_init(|| {
        let precompiles = Precompiles {
            inner: [
                sgxattest::ATTEST,
                sgxattest::VOLATILESET,
                sgxattest::VOLATILEGET,
                sgxattest::RANDOM,
                sgxattest::SEALINGKEY,
            ]
            .into(),
        };
        Box::new(precompiles)
    })
}

#[cfg(feature = "external_services")]
pub fn sm_precompiles() -> &'static Precompiles {
    static INSTANCE: OnceBox<Precompiles> = OnceBox::new();
    INSTANCE.get_or_init(|| {
        let precompiles = Precompiles {
            inner: [services_manager::RUN].into(),
        };
        Box::new(precompiles)
    })
}
