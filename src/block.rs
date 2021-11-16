use crate::signature::{Signature, PUBLIC_KEY_SIZE};

struct Coin(u64);

struct Address([u8; PUBLIC_KEY_SIZE]);

// The number of bytes in a block hash.
const BLOCK_HASH_SIZE: usize = blake3::OUT_LEN;

struct BlockHash([u8; BLOCK_HASH_SIZE]);

// The number of bytes in a transaction hash.
const TRANSACTION_HASH_SIZE: usize = blake3::OUT_LEN;

struct TransactionHash([u8; TRANSACTION_HASH_SIZE]);

struct Header {
    previous: BlockHash,
    height: u64,
    miner: Address,
    transaction_count: u64,
    transaction_hash: TransactionHash,
}

struct Transaction {
    from: Address,
    to: Address,
    amount: Coin,
    fee: Coin,
    counter: TransactionCounter,
    signature: Signature,
}

struct TransactionCounter(u64);

const BLOCK_SIZE: usize = 1 << 20;
const MAX_TRANSACTIONS: usize = BLOCK_SIZE / core::mem::size_of::<Transaction>();

struct Block {
    header: Header,
    transactions: [Transaction; BLOCK_SIZE],
}
