#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, xdr::ToXdr, Address,
    BytesN, Env, Symbol, Val, Vec,
};

#[cfg(test)]
mod test;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum TimelockError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    InsufficientDelay = 4,
    ProposalNotFound = 5,
    ProposalNotReady = 6,
    InvalidDelay = 8,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    MinDelay,
    Admin,
    Proposer(Address),
    Executor(Address),
    Canceller(Address),
    Proposal(BytesN<32>), // Hash -> ReadyTimestamp
}

#[contract]
pub struct TimelockController;

#[contractimpl]
impl TimelockController {
    /// Initialize the timelock with an admin, minimum delay, and optional initial roles.
    pub fn init(
        env: Env,
        admin: Address,
        min_delay: u64,
        proposers: Vec<Address>,
        executors: Vec<Address>,
    ) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(&env, TimelockError::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::MinDelay, &min_delay);

        for proposer in proposers.iter() {
            env.storage()
                .instance()
                .set(&DataKey::Proposer(proposer), &true);
        }
        for executor in executors.iter() {
            env.storage()
                .instance()
                .set(&DataKey::Executor(executor), &true);
        }
    }

    /// Accessors
    pub fn get_min_delay(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::MinDelay)
            .unwrap_or(0)
    }

    pub fn is_proposer(env: Env, address: Address) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Proposer(address))
            .unwrap_or(false)
    }

    pub fn is_executor(env: Env, address: Address) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Executor(address))
            .unwrap_or(false)
    }

    pub fn is_canceller(env: Env, address: Address) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Canceller(address))
            .unwrap_or(false)
    }

    /// Role Management (Admin only)
    pub fn set_proposer(env: Env, admin: Address, address: Address, active: bool) {
        admin.require_auth();
        check_admin(&env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::Proposer(address), &active);
    }

    pub fn set_executor(env: Env, admin: Address, address: Address, active: bool) {
        admin.require_auth();
        check_admin(&env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::Executor(address), &active);
    }

    pub fn set_canceller(env: Env, admin: Address, address: Address, active: bool) {
        admin.require_auth();
        check_admin(&env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::Canceller(address), &active);
    }

    pub fn update_delay(env: Env, admin: Address, new_delay: u64) {
        admin.require_auth();
        check_admin(&env, &admin);
        env.storage().instance().set(&DataKey::MinDelay, &new_delay);
    }

    /// Core Logic
    pub fn schedule(
        env: Env,
        proposer: Address,
        target: Address,
        fn_name: Symbol,
        args: Vec<Val>,
        salt: BytesN<32>,
        delay: u64,
    ) -> BytesN<32> {
        proposer.require_auth();
        if !Self::is_proposer(env.clone(), proposer) {
            panic_with_error!(&env, TimelockError::Unauthorized);
        }

        let min_delay = Self::get_min_delay(env.clone());
        if delay < min_delay {
            panic_with_error!(&env, TimelockError::InsufficientDelay);
        }

        let hash = compute_hash(&env, &target, &fn_name, &args, &salt);
        if env
            .storage()
            .instance()
            .has(&DataKey::Proposal(hash.clone()))
        {
            panic_with_error!(&env, TimelockError::AlreadyInitialized);
        }

        let ready_timestamp = env.ledger().timestamp() + delay;
        env.storage()
            .instance()
            .set(&DataKey::Proposal(hash.clone()), &ready_timestamp);

        env.events().publish(
            (Symbol::new(&env, "scheduled"), hash.clone()),
            (target, fn_name, ready_timestamp),
        );

        hash
    }

    pub fn execute(
        env: Env,
        executor: Address,
        target: Address,
        fn_name: Symbol,
        args: Vec<Val>,
        salt: BytesN<32>,
    ) -> Val {
        executor.require_auth();
        if !Self::is_executor(env.clone(), executor) {
            panic_with_error!(&env, TimelockError::Unauthorized);
        }

        let hash = compute_hash(&env, &target, &fn_name, &args, &salt);
        let ready_timestamp: u64 = env
            .storage()
            .instance()
            .get(&DataKey::Proposal(hash.clone()))
            .unwrap_or_else(|| panic_with_error!(&env, TimelockError::ProposalNotFound));

        if env.ledger().timestamp() < ready_timestamp {
            panic_with_error!(&env, TimelockError::ProposalNotReady);
        }

        // Mark as executed (remove from storage)
        env.storage()
            .instance()
            .remove(&DataKey::Proposal(hash.clone()));

        env.events().publish(
            (Symbol::new(&env, "executed"), hash),
            (target.clone(), fn_name.clone()),
        );

        // Call the target contract
        env.invoke_contract(&target, &fn_name, args)
    }

    pub fn cancel(env: Env, canceller: Address, hash: BytesN<32>) {
        canceller.require_auth();
        if !Self::is_canceller(env.clone(), canceller.clone())
            && !Self::is_proposer(env.clone(), canceller)
        {
            panic_with_error!(&env, TimelockError::Unauthorized);
        }

        if !env
            .storage()
            .instance()
            .has(&DataKey::Proposal(hash.clone()))
        {
            panic_with_error!(&env, TimelockError::ProposalNotFound);
        }

        env.storage()
            .instance()
            .remove(&DataKey::Proposal(hash.clone()));

        env.events()
            .publish((Symbol::new(&env, "canceled"), hash), ());
    }
}

fn check_admin(env: &Env, address: &Address) {
    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .unwrap_or_else(|| panic_with_error!(env, TimelockError::NotInitialized));
    if admin != *address {
        panic_with_error!(env, TimelockError::Unauthorized);
    }
}

fn compute_hash(
    env: &Env,
    target: &Address,
    fn_name: &Symbol,
    args: &Vec<Val>,
    salt: &BytesN<32>,
) -> BytesN<32> {
    // Collect all data into a vector for hashing
    let mut data = Vec::new(env);
    data.push_back(target.to_val());
    data.push_back(fn_name.to_val());
    for arg in args.iter() {
        data.push_back(arg);
    }
    data.push_back(salt.to_val());

    // Use SHA256 on the XDR representation of the data
    env.crypto().sha256(&data.to_xdr(env)).into()
}
