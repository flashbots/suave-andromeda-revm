use std::sync::Arc;

use revm::inspectors::TracerEip3155;
use revm::primitives::{Env, SpecId::SHANGHAI};
use revm::{inspector_handle_register, Database, Handler};
use revm::{Evm, EvmBuilder};

use crate::andromeda_precompiles;

pub fn new_andromeda_revm<'a, DB: Database>(
    db: &'a mut DB,
    env: Box<Env>,
) -> Evm<'a, (), &'a mut DB> {
    let builder = EvmBuilder::default();
    let builder = builder.with_db(db);
    let builder = builder.with_env(env);

    let handler = Handler::mainnet_with_spec(SHANGHAI);
    let builder = builder.with_handler(handler);
    let builder = builder.append_handler_register(|handler| {
        let precompiles = handler.pre_execution.load_precompiles();
        handler.pre_execution.load_precompiles = Arc::new(move || {
            let mut precompiles = precompiles.clone();
            precompiles.extend(andromeda_precompiles());
            precompiles
        });
    });

    builder.build()
}

pub fn new_andromeda_revm_wi<'a, DB: Database>(
    db: &'a mut DB,
    env: Box<Env>,
    inspector: TracerEip3155,
) -> Evm<'a, TracerEip3155, &'a mut DB> {
    let builder = EvmBuilder::default();
    let builder = builder.with_db(db);
    let builder = builder.with_env(env);

    let handler = Handler::mainnet_with_spec(SHANGHAI);
    let builder = builder.with_handler(handler);

    let builder = builder.with_external_context(inspector);
    let builder = builder.append_handler_register(inspector_handle_register);

    let builder = builder.append_handler_register(|handler| {
        let precompiles = handler.pre_execution.load_precompiles();
        handler.pre_execution.load_precompiles = Arc::new(move || {
            let mut precompiles = precompiles.clone();
            precompiles.extend(andromeda_precompiles());
            precompiles
        });
    });

    builder.build()
}
