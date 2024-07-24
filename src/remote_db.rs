use revm::primitives::AccessListItem;
use std::collections::HashMap;
use tokio::runtime::Handle;
use tokio::task::block_in_place;

use ethers::prelude::Address as EthersAddress;
use ethers::types::{H256 as EH256, U256 as EU256};

use revm::db::{AccountState, CacheDB};
use revm::primitives::{hash_map::Entry, AccountInfo, Address, Bytecode, Bytes, B256, U256};
use revm::{Database, DatabaseRef};

use execution::rpc::ExecutionRpc;
use execution::ExecutionClient;
use helios::types::BlockTag::{Latest, Number};

pub trait StateProvider {
    fn fetch_account(
        &mut self,
        address: Address,
        slots: Option<&[EH256]>,
    ) -> Result<(AccountInfo, HashMap<EH256, EU256>), StateProviderError>;
    fn fetch_storage(&mut self, address: Address, index: U256) -> Result<U256, StateProviderError>;
    fn fetch_block_hash(&mut self, number: U256) -> Result<B256, StateProviderError>;
}

impl<R: ExecutionRpc> StateProvider for ExecutionClient<R> {
    fn fetch_account(
        &mut self,
        address: Address,
        slots: Option<&[EH256]>,
    ) -> Result<(AccountInfo, HashMap<EH256, EU256>), StateProviderError> {
        match block_in_place(|| {
            Handle::current().block_on(self.get_account(
                &EthersAddress::from_slice(address.as_slice()),
                slots,
                Latest,
            ))
        }) {
            Ok(acc) => Ok((
                AccountInfo::new(
                    acc.balance.into(),
                    acc.nonce,
                    B256::from(acc.code_hash.to_fixed_bytes()),
                    Bytecode::new_raw(Bytes::from_iter(acc.code.into_iter())),
                ),
                acc.slots,
            )),
            Err(err) => Err(StateProviderError::FetchFailed(err.to_string())),
        }
    }

    fn fetch_storage(&mut self, address: Address, index: U256) -> Result<U256, StateProviderError> {
        let slots = Box::new([EH256::from_slice(index.to_be_bytes_vec().as_slice())]);
        match block_in_place(|| {
            Handle::current().block_on(self.get_account(
                &EthersAddress::from_slice(address.as_slice()),
                Some(slots.as_ref()),
                Latest,
            ))
        }) {
            Ok(acc) => {
                if let Some(v) = acc.slots.get(&slots[0]) {
                    Ok(U256::from_limbs(v.0))
                } else {
                    Ok(U256::ZERO)
                }
            }
            Err(err) => Err(StateProviderError::FetchFailed(err.to_string())),
        }
    }

    fn fetch_block_hash(&mut self, number: U256) -> Result<B256, StateProviderError> {
        match block_in_place(|| {
            Handle::current().block_on(self.get_block(Number(number.as_limbs()[0]), false))
        }) {
            Ok(block) => Ok(B256::from_slice(block.hash.to_fixed_bytes().as_slice())),
            Err(err) => Err(StateProviderError::FetchFailed(err.to_string())),
        }
    }
}

#[derive(Debug)]
pub enum StateProviderError {
    FetchFailed(String),
}

#[derive(Debug, Clone)]
pub struct RemoteDB<SP: StateProvider, ExtDB: DatabaseRef> {
    pub state_provider: SP,
    pub db: CacheDB<ExtDB>,
}

impl<SP: StateProvider, ExtDB: DatabaseRef> RemoteDB<SP, ExtDB> {
    pub fn new(state_provider: SP, db: CacheDB<ExtDB>) -> Self {
        Self { state_provider, db }
    }

    pub fn prefetch_from_revm_access_list(
        &mut self,
        access_list: Vec<AccessListItem>,
    ) -> Result<(), StateProviderError> {
        let ethers_slots_vec = Vec::from_iter(access_list.iter().map(|it| {
            let ethers_slots = Vec::from_iter(
                it.storage_keys
                    .iter()
                    .map(|slot| EH256::from_slice(slot.as_slice())),
            );
            (it.address, ethers_slots)
        }));

        let ethers_access_list_slices = Vec::from_iter(
            ethers_slots_vec
                .iter()
                .map(|(addr, slots_vec)| (*addr, Some(slots_vec.as_slice()))),
        );

        self.prefetch(ethers_access_list_slices)
    }

    pub fn prefetch(
        &mut self,
        access_list: Vec<(Address, Option<&[EH256]>)>,
    ) -> Result<(), StateProviderError> {
        for (addr, accessed_slots) in access_list {
            match self.state_provider.fetch_account(addr, accessed_slots) {
                Err(_) => {}
                Ok((acc, slots)) => {
                    self.db.insert_account_info(addr, acc);
                    for (slot, value) in &slots {
                        if let Err(_err) = self.db.insert_account_storage(
                            addr,
                            U256::from_be_slice(slot.as_bytes()),
                            U256::from_limbs(value.0),
                        ) {
                            // wat do?
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum RemoteDBError<DBError> {
    State(StateProviderError),
    Database(DBError),
}

/* Not needed and should not be called
impl<ExtDB: DatabaseRef> DatabaseCommit for RemoteDB<ExtDB> {
    fn commit(&mut self, changes: HashMap<Address, Account>) {}
}
*/

impl<SP: StateProvider, ExtDB: DatabaseRef> Database for RemoteDB<SP, ExtDB> {
    type Error = RemoteDBError<ExtDB::Error>;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        match self.db.accounts.entry(address) {
            Entry::Occupied(entry) => Ok(entry.into_mut().info()),
            Entry::Vacant(_) => {
                if let Ok((acc, _)) = self.state_provider.fetch_account(address, None) {
                    self.db.insert_account_info(address, acc);
                }

                match self.db.basic(address) {
                    Ok(info) => Ok(info),
                    Err(err) => Err(RemoteDBError::Database(err)),
                }
            }
        }
    }

    /* Only called if basic() does not return code */
    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        // Make sure code is returned by basic()!
        // If for some reason it's not, adjust this function to separately fetch the code

        match self.db.code_by_hash(code_hash) {
            Ok(info) => Ok(info),
            Err(err) => Err(RemoteDBError::Database(err)),
        }
    }

    // It is assumed that account is already loaded.
    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        match self.db.accounts.entry(address) {
            Entry::Vacant(_) => {
                // Note: if this doesn't hold (it should according to the comments), insert the account
                panic!("{} storage for non-loaded address requested", address)
            }
            Entry::Occupied(mut acc_entry) => {
                let acc_entry = acc_entry.get_mut();
                match acc_entry.storage.entry(index) {
                    Entry::Occupied(entry) => Ok(*entry.get()),
                    Entry::Vacant(entry) => {
                        if matches!(
                            acc_entry.account_state,
                            AccountState::StorageCleared | AccountState::NotExisting
                        ) {
                            Ok(U256::ZERO)
                        } else {
                            match self.state_provider.fetch_storage(address, index) {
                                Ok(slot) => {
                                    entry.insert(slot);
                                    Ok(slot)
                                }
                                Err(_) => {
                                    entry.insert(U256::ZERO);
                                    Ok(U256::ZERO) // Should we
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        /* TODO: consider whether we should fetch the block hash, maybe we should just refuse */
        match self.db.block_hashes.entry(U256::from(number)) {
            Entry::Occupied(entry) => Ok(*entry.get()),
            Entry::Vacant(entry) => {
                match self.state_provider.fetch_block_hash(U256::from(number)) {
                    Ok(hash) => {
                        entry.insert(hash);
                        Ok(hash)
                    }
                    Err(_) => match self.db.block_hash(number) {
                        Ok(hash) => Ok(hash),
                        Err(err) => Err(RemoteDBError::Database(err)),
                    },
                }
            }
        }
    }
}
