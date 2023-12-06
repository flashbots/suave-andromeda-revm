use ethers::core::types::{Block as EthersBlock, Bytes, TxHash};
use helios::types::{Block as HeliosBlock, Transactions};

use ethers::types::H256 as EH256;
use revm::primitives::{Address, U256};

pub fn revm_access_list_to_ethers(
    revm_access_list: Vec<(Address, Vec<U256>)>,
) -> Vec<(Address, Vec<EH256>)> {
    let mut ethers_access_list: Vec<(Address, Vec<EH256>)> = Vec::new();

    for (addr, revm_slots) in revm_access_list {
        let mut ethers_slots: Vec<EH256> = Vec::new();
        for slot in revm_slots {
            ethers_slots.push(EH256::from_slice(slot.as_le_slice()));
        }
        ethers_access_list.push((addr, ethers_slots));
    }

    ethers_access_list
}

#[derive(Debug)]
pub enum BlockError {
    NumberEmpty,
    HashEmpty,
}

pub fn ethers_block_to_helios(block: EthersBlock<TxHash>) -> Result<HeliosBlock, BlockError> {
    if block.hash.is_none() {
        return Err(BlockError::HashEmpty);
    }
    let hash = block.hash.unwrap();

    if block.number.is_none() {
        return Err(BlockError::NumberEmpty);
    }
    let number = block.number.unwrap();

    Ok(HeliosBlock {
        number,
        base_fee_per_gas: block.base_fee_per_gas.unwrap_or_default(),
        difficulty: block.difficulty,
        extra_data: block.extra_data,
        gas_limit: block.gas_limit.as_u64().into(),
        gas_used: block.gas_used.as_u64().into(),
        hash,
        logs_bloom: Bytes::from_iter(block.logs_bloom.unwrap().as_bytes().into_iter()),
        miner: block.author.unwrap_or_default(),
        mix_hash: block.mix_hash.unwrap_or_default(),
        nonce: String::from(""), // block.seal_fields?
        parent_hash: block.parent_hash,
        receipts_root: block.receipts_root,
        sha3_uncles: block.uncles_hash,
        size: block.size.unwrap_or_default().as_u64().into(),
        state_root: block.state_root,
        timestamp: block.timestamp.as_u64().into(),
        total_difficulty: block.total_difficulty.unwrap_or_default().as_u64().into(),
        transactions: Transactions::Hashes(block.transactions),
        transactions_root: block.transactions_root,
        uncles: block.uncles,
    })
}
