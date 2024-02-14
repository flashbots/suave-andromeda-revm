use revm::precompile::Precompiles;

use once_cell::race::OnceBox;

use crate::precompiles::sgxattest;
use crate::precompiles::crypto;

pub fn andromeda_precompiles() -> &'static Precompiles {
    static INSTANCE: OnceBox<Precompiles> = OnceBox::new();
    INSTANCE.get_or_init(|| {
        let mut precompiles: Precompiles = Precompiles::istanbul().clone();
        precompiles.extend(sgx_precompiles().inner.clone().into_iter());
        precompiles.extend(crypto_precompiles().inner.clone().into_iter());
        Box::new(precompiles.to_owned())
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

pub fn crypto_precompiles() -> &'static Precompiles {
    static INSTANCE: OnceBox<Precompiles> = OnceBox::new();
    INSTANCE.get_or_init(|| {
        let precompiles = Precompiles {
            inner: [crypto::SHA512].into(),
        };
        Box::new(precompiles)
    })
}
