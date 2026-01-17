//! MWC Supply Verifier
//!
//! Cryptographically verifies that the MWC supply is valid by checking:
//!   ΣUTXO commitments == Σkernel excesses + offset·G + reward·H
//!
//! This proves no coins were created out of thin air - every output is backed
//! by either a kernel (transaction) or the coinbase reward.
//!
//! Requirements:
//! - A fully synced MWC node with chain data accessible
//! - The chain_data path (typically ~/.mwc/main/chain_data)

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;

use mwc_chain::store::ChainStore;
use mwc_chain::txhashset::TxHashSet;
use mwc_core::consensus::{calc_mwc_block_overage, MWC_BASE};
use mwc_core::core::hash::Hashed;
use mwc_core::core::pmmr::ReadablePMMR;
use mwc_core::global::{self, ChainTypes};
use mwc_util::secp::key::SecretKey;
use mwc_util::secp::pedersen::Commitment;
use mwc_util::secp::{ContextFlag, Secp256k1};
use mwc_util::to_hex;

#[derive(Parser, Debug)]
#[command(name = "mwc-supply-verifier")]
#[command(about = "Cryptographically verify MWC supply integrity")]
#[command(version)]
struct Args {
    /// Path to MWC chain data directory
    #[arg(long, default_value = "~/.mwc/main/chain_data")]
    chain_path: String,
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}{}", home.to_string_lossy(), &path[1..]);
        }
    }
    path.to_string()
}

fn main() -> Result<()> {
    let args = Args::parse();
    let chain_path = expand_tilde(&args.chain_path);

    println!("MWC Supply Verifier");
    println!("===================");
    println!();

    verify_supply(&chain_path)?;

    Ok(())
}

fn verify_supply(chain_path: &str) -> Result<()> {
    // Initialize MWC globals for mainnet
    global::set_local_chain_type(ChainTypes::Mainnet);
    let secp = Secp256k1::with_caps(ContextFlag::Commit);

    // Check if chain data exists
    let chain_data_path = Path::new(chain_path);
    if !chain_data_path.exists() {
        anyhow::bail!(
            "Chain data not found at: {}\n\
             Make sure the MWC node is running and fully synced.\n\
             You can specify a custom path with --chain-path",
            chain_path
        );
    }

    println!("Opening chain store at: {}", chain_path);

    // Open chain store and get the current tip
    let store = Arc::new(ChainStore::new(chain_path)?);
    let pinned = store.head_header().map_err(|e| {
        anyhow::anyhow!(
            "Could not read chain head: {}\n\
             The node may still be syncing. Supply verification requires a fully synced node.",
            e
        )
    })?;

    let tip_height = pinned.height;
    println!("Pinned tip height: {}", tip_height);
    println!();

    // ============ Step 1: Sum all UTXO commitments (LHS) ============
    println!("Step 1: Collecting UTXO commitments...");

    let txhashset = TxHashSet::open(chain_path.to_string(), store.clone(), None, &secp)?;
    let output_pmmr = txhashset.output_pmmr_at(&pinned);

    let mut utxo_commits: Vec<Commitment> = Vec::new();
    let mut utxo_count: usize = 0;

    for pos in output_pmmr.leaf_pos_iter() {
        if let Some(output_id) = output_pmmr.get_data(pos) {
            let commit = output_id.commitment();
            utxo_commits.push(Commitment(commit.0));
            utxo_count += 1;
        }
    }

    println!("  Collected {} UTXOs at height {}", utxo_count, tip_height);

    let lhs_commit = secp.commit_sum(utxo_commits, vec![])?;

    // ============ Step 2: Sum all kernel excesses ============
    println!("Step 2: Collecting kernel excesses (walking chain to genesis)...");

    let mut kernel_excess_commits: Vec<Commitment> = Vec::new();
    let mut collected_kernels: usize = 0;

    let mut walk = pinned.clone();
    loop {
        let block = store.get_block(&walk.hash()).map_err(|e| {
            anyhow::anyhow!(
                "Block not found at height {} - node is still syncing: {}",
                walk.height,
                e
            )
        })?;

        for k in block.kernels() {
            kernel_excess_commits.push(Commitment(k.excess.0));
            collected_kernels += 1;
        }

        if walk.height % 100_000 == 0 && walk.height > 0 {
            println!("  ... at height {}", walk.height);
        }

        if walk.height == 0 {
            break;
        }

        walk = store.get_previous_header(&walk).map_err(|e| {
            anyhow::anyhow!(
                "Header not found at height {} - node is still syncing: {}",
                walk.height - 1,
                e
            )
        })?;
    }

    println!("  Collected {} kernel excesses", collected_kernels);

    let sum_excesses_commit = secp.commit_sum(kernel_excess_commits, vec![])?;

    // ============ Step 3: Compute offset and reward commitments ============
    println!("Step 3: Computing offset and reward commitments...");

    let offset_bf = pinned.total_kernel_offset;
    let offset_sk = SecretKey::from_slice(&secp, offset_bf.as_ref())?;
    let offset_commit = secp.commit(0, offset_sk)?;

    let total_reward = calc_mwc_block_overage(tip_height, true);
    let reward_mwc = total_reward as f64 / MWC_BASE as f64;
    println!(
        "  Total reward at height {}: {:.9} MWC",
        tip_height, reward_mwc
    );

    let reward_commit = secp.commit_value(total_reward)?;

    // ============ Step 4: Compute RHS and compare ============
    println!("Step 4: Verifying supply equation...");
    println!();

    let rhs_commit = secp.commit_sum(
        vec![sum_excesses_commit, offset_commit, reward_commit],
        vec![],
    )?;

    println!("Supply Equation:");
    println!("  ΣUTXO == Σkernels + offset·G + reward·H");
    println!();
    println!("  LHS (ΣUTXO):          {}", to_hex(&lhs_commit.0));
    println!("  RHS (Σkern+off+rew):  {}", to_hex(&rhs_commit.0));
    println!();

    if lhs_commit == rhs_commit {
        println!("RESULT: MWC supply is valid!");
        println!();
        println!("This cryptographically proves that no MWC were created out of thin air.");
        println!("Every coin in existence is backed by either:");
        println!("  - A valid transaction kernel, or");
        println!("  - The coinbase block reward");
        Ok(())
    } else {
        anyhow::bail!(
            "SUPPLY MISMATCH DETECTED!\n\
             LHS: {}\n\
             RHS: {}\n\
             This should never happen on a valid chain.",
            to_hex(&lhs_commit.0),
            to_hex(&rhs_commit.0)
        )
    }
}
