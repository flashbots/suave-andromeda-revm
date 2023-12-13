use consensus::errors::ConsensusError;

use eyre::Result;
use ssz_rs::prelude::*;
use tracing::{error, info};

use common::types::Block;

use reth_primitives::{
    B64,
    Bloom,
    Header,
    hex::FromHex,
    Address,
    revm_primitives::FixedBytes,
    revm::env::recover_header_signer
};

#[derive(Debug)]
pub struct Consensus {
    pub latest_block: Option<Block>,
    signers: Vec<Address>,
}

fn verify(block: &Block) -> Address {
    let header = extract_header(&block).unwrap();

    // TODO: can this kill the client if it recieves a malicous block?
    let creator: Address = recover_header_signer(&header).unwrap_or_else(|| {
        panic!(
            "Failed to recover Clique Consensus signer from header ({}, {}) using extradata {}",
            header.number, header.hash_slow(), header.extra_data
        )
    });

    return creator;
}

pub fn extract_header(block: &Block) -> Result<Header> {
    Ok(Header {   
        parent_hash: FixedBytes::new(block.parent_hash.into()),
        ommers_hash: FixedBytes::new(block.sha3_uncles.into()),
        beneficiary: Address::new(block.miner.into()),
        state_root: FixedBytes::new(block.state_root.into()),
        transactions_root: FixedBytes::new(block.transactions_root.into()),
        receipts_root: FixedBytes::new(block.receipts_root.into()),
        withdrawals_root: None,
        logs_bloom: Bloom { 0: FixedBytes::new(block.logs_bloom.to_vec().try_into().unwrap()) },
        timestamp: block.timestamp.as_u64(),
        mix_hash: FixedBytes::new(block.mix_hash.into()),
        nonce: u64::from_be_bytes(B64::from_hex(block.nonce.clone())?.try_into()?),
        base_fee_per_gas: None,
        number: block.number.as_u64(),
        gas_limit: block.gas_limit.as_u64(),
        difficulty: block.difficulty.into(),
        gas_used: block.gas_used.as_u64(),
        extra_data: block.extra_data.0.clone().into(),
        parent_beacon_block_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
    })
}

impl Consensus {
    pub fn new() -> Result<Self> {
        let signers = [
            Address::from_hex("0x0981717712ed2c4919fdbc27dfc804800a9eeff9")?,
            Address::from_hex("0x0e5b9aa4925ed1beeb08d1c5a92477a1b719baa7")?,
            Address::from_hex("0x0e8705e07bbe1ce2c39093df3d20aaa5120bfc7a")?,
        ].to_vec();

        Ok(Consensus {
            latest_block: None,
            signers,
        })
    }

    pub fn sync(&mut self, block: &Block) -> Result<(), ConsensusError> {
        let creator = verify(&block);

        if !self.signers.contains(&creator) {
            error!(
                target: "helios::consensus", 
                "sync block contains invalid block creator: {}",
                creator
            );
            return Err(ConsensusError::InvalidSignature.into());
        }

        info!(
            target: "helios::consensus",
            "PoA consensus client in sync with block: {}: {:#?}",
            &block.number, &block.hash
        );

        self.latest_block = Some(block.clone());

        Ok(())
    }

    pub fn advance(&mut self, block: &Block) -> Result<(), ConsensusError> {
        if self.latest_block.as_ref().unwrap().number.as_u64()+1 != block.number.as_u64() {
            error!(
                target: "helios::consensus", 
                "advance block recieved block with invalid block number: expected: {}, actual {}",
                self.latest_block.as_ref().unwrap().timestamp.as_u64()+1,
                block.timestamp
            );
            return Err(ConsensusError::NotRelevant.into());
        }
        let creator = verify(&block);

        if !self.signers.contains(&creator) {
            error!(
                target: "helios::consensus", 
                "advance block contains invalid block creator: {}",
                creator
            );
            return Err(ConsensusError::InvalidSignature.into());
        }

        info!(
            target: "helios::consensus",
            "PoA consensus client advanced to block {}: {:#?}",
            &block.number, &block.hash
        );

        self.latest_block = Some(block.clone());

        Ok(())
    }
}