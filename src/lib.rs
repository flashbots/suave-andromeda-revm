pub mod remote_db;
pub use remote_db::{RemoteDB, StateProvider};
pub mod utils;
pub use utils::ethers_block_to_helios;
pub mod stateful;
pub use stateful::StatefulExecutor;
pub mod consensus;

pub mod evm;
pub use evm::new_andromeda_revm;

pub mod precompiles {
    pub mod lib;
    pub mod services_manager;
    pub mod sgxattest;
    pub mod kettle_http;
}

pub use precompiles::lib::andromeda_precompiles;

#[cfg(feature = "external_services")]
pub mod external_services {
    pub mod common;
    pub mod builder {
        pub mod builder;
    }
    pub mod redis {
        pub mod pubsub;
        pub mod redis;
    }
    pub mod services_manager {
        pub mod services_manager;
    }
}

use revm::primitives::Address;

#[inline]
const fn u64_to_address(x: u64) -> Address {
    let x = x.to_be_bytes();
    Address::new([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7],
    ])
}
