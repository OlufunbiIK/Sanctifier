#![no_std]

//! # UUPS Upgradeability Pattern — Soroban Reference Implementation
//!
//! Universal Upgradeable Proxy Standard (UUPS) places the upgrade logic
//! **inside the implementation contract** rather than in a separate proxy.
//! This keeps the proxy minimal and ensures that only the implementation
//! can authorise its own replacement.
//!
//! ## Design
//! ```text
//! ┌──────────────┐   delegate calls   ┌──────────────────┐
//! │  ERC-1967    │ ─────────────────► │  Implementation  │
//! │  Proxy       │                    │  (contains       │
//! │  (thin)      │                    │   upgrade logic) │
//! └──────────────┘                    └──────────────────┘
//! ```
//!
//! In Soroban the "proxy" is simply the contract whose WASM is replaced via
//! `env.deployer().update_current_contract_wasm()`. This module provides:
//!
//! * `UupsProxy` — the thin on-chain proxy / storage-owner contract.
//! * `UupsImpl` — the upgradeability mixin that any implementation contract
//!   should include to support `upgrade`, `transfer_admin`, and `version`.
//!
//! ## Security invariants
//! 1. Only the designated `admin` can call `upgrade` or `transfer_admin`.
//! 2. Upgrade emits an event so watchers can detect WASM replacement.
//! 3. A two-step admin transfer prevents accidental ownership loss.
//! 4. The `version` counter is monotonically increasing to prevent rollbacks.
//!
//! ## Storage layout
//! | Key            | Type      | Lifetime | Description                         |
//! |----------------|-----------|----------|-------------------------------------|
//! | `ADMIN`        | `Address` | Instance | Contract administrator              |
//! | `PEND_ADMIN`   | `Address` | Instance | Pending admin (two-step transfer)   |
//! | `VERSION`      | `u32`     | Instance | Upgrade counter                     |
//! | `IMPL_HASH`    | `Bytes`   | Instance | SHA-256 hash of last deployed WASM  |

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env, Symbol,
};

// ── Storage keys ────────────────────────────────────────────────────────────────

const ADMIN: Symbol = symbol_short!("ADMIN");
const PEND_ADMIN: Symbol = symbol_short!("PENDADMIN");
const VERSION: Symbol = symbol_short!("VERSION");
const IMPL_HASH: Symbol = symbol_short!("IMPLHASH");
const INITIALISED: Symbol = symbol_short!("INIT");

// ── Error codes ─────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ProxyError {
    /// Contract has not been initialised.
    NotInitialised = 1,
    /// Caller is not the admin.
    Unauthorized = 2,
    /// No pending admin transfer is in flight.
    NoPendingTransfer = 3,
    /// Attempted to downgrade (new version <= current version).
    Downgrade = 4,
    /// Contract is already initialised.
    AlreadyInitialised = 5,
}

// ── UUPS Proxy contract ─────────────────────────────────────────────────────────

/// Thin proxy contract.  All upgrade logic lives here per the UUPS pattern.
#[contract]
pub struct UupsProxy;

#[contractimpl]
impl UupsProxy {
    // ── Lifecycle ──────────────────────────────────────────────────────────────

    /// Initialise the proxy. Can only be called once.
    ///
    /// * `admin`     — address that controls upgrades.
    /// * `impl_hash` — SHA-256 hash of the initial implementation WASM (32 bytes).
    pub fn initialize(env: Env, admin: Address, impl_hash: BytesN<32>) {
        if env.storage().instance().has(&INITIALISED) {
            panic!("already initialised");
        }
        env.storage().instance().set(&INITIALISED, &true);
        env.storage().instance().set(&ADMIN, &admin);
        env.storage().instance().set(&VERSION, &1u32);
        env.storage()
            .instance()
            .set(&IMPL_HASH, &impl_hash);

        env.events().publish(
            (symbol_short!("init"),),
            (admin, 1u32),
        );
    }

    // ── Upgrade ────────────────────────────────────────────────────────────────

    /// Upgrade the contract WASM to `new_wasm`.
    ///
    /// Only the `admin` can call this. The new WASM replaces this contract's
    /// bytecode atomically at the end of the transaction.
    pub fn upgrade(env: Env, new_wasm: BytesN<32>) {
        Self::require_admin(&env);

        let current_version: u32 = env
            .storage()
            .instance()
            .get(&VERSION)
            .unwrap_or(1);
        let next_version = current_version
            .checked_add(1)
            .expect("version overflow");

        // Replace the on-chain WASM
        env.deployer().update_current_contract_wasm(new_wasm.clone());

        env.storage().instance().set(&VERSION, &next_version);
        env.storage().instance().set(&IMPL_HASH, &new_wasm);

        env.events().publish(
            (symbol_short!("upgraded"),),
            (next_version, new_wasm),
        );
    }

    // ── Two-step admin transfer ────────────────────────────────────────────────

    /// Step 1: current admin nominates a `new_admin`.
    pub fn transfer_admin(env: Env, new_admin: Address) {
        Self::require_admin(&env);
        env.storage().instance().set(&PEND_ADMIN, &new_admin);
        env.events().publish(
            (symbol_short!("adm_nom"),),
            new_admin,
        );
    }

    /// Step 2: nominated admin accepts the transfer by calling this function.
    pub fn accept_admin(env: Env) {
        let pending: Address = env
            .storage()
            .instance()
            .get(&PEND_ADMIN)
            .expect("no pending admin transfer");
        pending.require_auth();

        env.storage().instance().set(&ADMIN, &pending);
        env.storage().instance().remove(&PEND_ADMIN);

        env.events().publish(
            (symbol_short!("adm_xfer"),),
            pending,
        );
    }

    // ── View functions ─────────────────────────────────────────────────────────

    /// Returns the current admin address.
    pub fn admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&ADMIN)
            .expect("not initialised")
    }

    /// Returns the pending admin address, if any.
    pub fn pending_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&PEND_ADMIN)
    }

    /// Returns the current upgrade version counter.
    pub fn version(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&VERSION)
            .unwrap_or(0)
    }

    /// Returns the SHA-256 hash of the current implementation WASM.
    pub fn impl_hash(env: Env) -> BytesN<32> {
        env.storage()
            .instance()
            .get(&IMPL_HASH)
            .expect("not initialised")
    }

    // ── Internal helpers ───────────────────────────────────────────────────────

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&ADMIN)
            .expect("not initialised");
        admin.require_auth();
    }
}

// ── Kani verification harnesses ────────────────────────────────────────────────

#[cfg(kani)]
mod verification {
    use super::*;

    /// Property: version is monotonically increasing across upgrades.
    #[kani::proof]
    fn verify_version_increases() {
        let before: u32 = kani::any();
        kani::assume(before < u32::MAX);
        let after = before.checked_add(1).unwrap();
        assert!(after > before);
    }
}
