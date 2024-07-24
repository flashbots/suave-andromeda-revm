use revm::primitives::{Env, ShanghaiSpec};
use revm::{Database, EVMImpl, Inspector};

use crate::andromeda_precompiles;

pub fn new_andromeda_revm<'a, DB: Database>(
    db: &'a mut DB,
    env: &'a mut Env,
    inspector: Option<&'a mut dyn Inspector<DB>>,
) -> EVMImpl<'a, ShanghaiSpec, DB> {
    EVMImpl::<ShanghaiSpec, _>::new_with_spec(
        db,
        env,
        inspector,
        andromeda_precompiles().to_owned(),
    )
}
