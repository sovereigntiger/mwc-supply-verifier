# MWC Supply Verifier

Cryptographically verify that the MWC (MimbleWimble Coin) supply is valid.

## What It Does

This tool verifies the fundamental MimbleWimble supply equation:

```
ΣUTXO commitments == Σkernel excesses + offset·G + reward·H
```

This proves that **no coins were created out of thin air**. Every MWC in existence is backed by either:
- A valid transaction kernel, or
- The coinbase block reward

## Requirements

- A fully synced MWC **archive node** (regular nodes prune old block data)
- Access to the node's chain data directory (typically `~/.mwc/main/chain_data`)
- Rust toolchain

## Building

```bash
cargo build --release
```

## Usage

```bash
# Using default chain path (~/.mwc/main/chain_data)
./target/release/mwc-supply-verifier

# With custom chain path
./target/release/mwc-supply-verifier --chain-path /path/to/chain_data
```

## How It Works

1. **Collects all UTXOs** - Iterates through the entire UTXO set and sums their Pedersen commitments
2. **Collects all kernels** - Walks the blockchain from tip to genesis, collecting all kernel excesses
3. **Computes offset & reward** - Gets the total kernel offset and calculates total block rewards
4. **Verifies the equation** - Checks that LHS (UTXOs) equals RHS (kernels + offset + reward)

If the equation balances, the supply is cryptographically proven to be valid.

## Example Output

```
MWC Supply Verifier
===================

Opening chain store at: /home/user/.mwc/main/chain_data
Pinned tip height: 1937000

Step 1: Collecting UTXO commitments...
  Collected 125000 UTXOs at height 1937000

Step 2: Collecting kernel excesses (walking chain to genesis)...
  ... at height 1900000
  ... at height 1800000
  ...
  Collected 2500000 kernel excesses

Step 3: Computing offset and reward commitments...
  Total reward at height 1937000: 19370000.000000000 MWC

Step 4: Verifying supply equation...

Supply Equation:
  ΣUTXO == Σkernels + offset·G + reward·H

  LHS (ΣUTXO):          09abc123...
  RHS (Σkern+off+rew):  09abc123...

RESULT: MWC supply is valid!

This cryptographically proves that no MWC were created out of thin air.
Every coin in existence is backed by either:
  - A valid transaction kernel, or
  - The coinbase block reward
```

## License

MIT
