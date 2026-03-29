#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, xdr::ToXdr, Address, Bytes,
    Env, IntoVal, Symbol, Val, Vec,
};

#[cfg(test)]
mod test;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    InvalidThreshold = 3,
    InsufficientSigners = 4,
    Unauthorized = 5,
    ProposalNotFound = 6,
    AlreadyApproved = 7,
    ThresholdNotMet = 8,
    AlreadyExecuted = 9,
    AlreadyCancelled = 10,
    InvalidArguments = 11,
}

#[contracttype]
pub enum DataKey {
    Signers,
    Threshold,
    Proposal(Bytes),          // Proposal Hash -> Info
    Approval(Bytes, Address), // (Hash, Signer) -> bool
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct ProposalInfo {
    pub approval_count: u32,
    pub executed: bool,
    pub cancelled: bool,
}

#[contract]
pub struct MultisigWallet;

#[contractimpl]
impl MultisigWallet {
    /// Initialize the multisig wallet with a list of signers and a threshold.
    pub fn init(env: Env, signers: Vec<Address>, threshold: u32) {
        if env.storage().instance().has(&DataKey::Threshold) {
            env.panic_with_error(Error::AlreadyInitialized);
        }
        if threshold == 0 || threshold > signers.len() {
            env.panic_with_error(Error::InvalidThreshold);
        }

        env.storage().instance().set(&DataKey::Signers, &signers);
        env.storage()
            .instance()
            .set(&DataKey::Threshold, &threshold);
    }

    /// Create a new proposal.
    pub fn propose(
        env: Env,
        target: Address,
        function: Symbol,
        args: Vec<Val>,
        salt: Bytes,
    ) -> Bytes {
        let hash = Self::calculate_hash(&env, &target, &function, &args, &salt);

        if env
            .storage()
            .persistent()
            .has(&DataKey::Proposal(hash.clone()))
        {
            return hash;
        }

        let info = ProposalInfo {
            approval_count: 0,
            executed: false,
            cancelled: false,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(hash.clone()), &info);

        env.events().publish(
            (symbol_short!("proposed"), hash.clone()),
            (target, function),
        );

        hash
    }

    /// Approve a proposal.
    pub fn approve(env: Env, signer: Address, hash: Bytes) {
        signer.require_auth();

        let signers: Vec<Address> = env.storage().instance().get(&DataKey::Signers).unwrap();
        if !signers.contains(&signer) {
            env.panic_with_error(Error::Unauthorized);
        }

        let mut info: ProposalInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(hash.clone()))
            .unwrap_or_else(|| env.panic_with_error(Error::ProposalNotFound));

        if info.executed {
            env.panic_with_error(Error::AlreadyExecuted);
        }
        if info.cancelled {
            env.panic_with_error(Error::AlreadyCancelled);
        }

        let approval_key = DataKey::Approval(hash.clone(), signer.clone());
        if env.storage().persistent().has(&approval_key) {
            env.panic_with_error(Error::AlreadyApproved);
        }

        info.approval_count += 1;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(hash.clone()), &info);
        env.storage().persistent().set(&approval_key, &true);

        env.events()
            .publish((symbol_short!("approved"), hash), signer.clone());
    }

    /// Execute a proposal if the threshold is met.
    pub fn execute(
        env: Env,
        target: Address,
        function: Symbol,
        args: Vec<Val>,
        salt: Bytes,
    ) -> Val {
        let hash = Self::calculate_hash(&env, &target, &function, &args, &salt);

        let mut info: ProposalInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(hash.clone()))
            .unwrap_or_else(|| env.panic_with_error(Error::ProposalNotFound));

        let threshold: u32 = env.storage().instance().get(&DataKey::Threshold).unwrap();

        if info.approval_count < threshold {
            env.panic_with_error(Error::ThresholdNotMet);
        }
        if info.executed {
            env.panic_with_error(Error::AlreadyExecuted);
        }
        if info.cancelled {
            env.panic_with_error(Error::AlreadyCancelled);
        }

        info.executed = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(hash.clone()), &info);

        // Native routing for self-calls to bypass recursion and authorization issues.
        // This is the most robust way to handle administrative self-governance in Soroban.
        let result = if target == env.current_contract_address() {
            if function == Symbol::new(&env, "add_signer") {
                let signer: Address = args.get(0).unwrap().into_val(&env);
                Self::internal_add_signer(&env, signer);
                ().into_val(&env)
            } else if function == Symbol::new(&env, "remove_signer") {
                let signer: Address = args.get(0).unwrap().into_val(&env);
                Self::internal_remove_signer(&env, signer);
                ().into_val(&env)
            } else if function == Symbol::new(&env, "set_threshold") {
                let threshold: u32 = args.get(0).unwrap().into_val(&env);
                Self::internal_set_threshold(&env, threshold);
                ().into_val(&env)
            } else if function == Symbol::new(&env, "cancel") {
                let hash_to_cancel: Bytes = args.get(0).unwrap().into_val(&env);
                Self::internal_cancel(&env, hash_to_cancel);
                ().into_val(&env)
            } else {
                env.panic_with_error(Error::InvalidArguments);
            }
        } else {
            env.invoke_contract::<Val>(&target, &function, args)
        };

        env.events()
            .publish((symbol_short!("executed"), hash), target);
        result
    }

    /// Public wrapper for cancel (requires contract's own auth for top-level call)
    pub fn cancel(env: Env, hash: Bytes) {
        env.current_contract_address().require_auth();
        Self::internal_cancel(&env, hash);
    }

    pub fn add_signer(env: Env, signer: Address) {
        env.current_contract_address().require_auth();
        Self::internal_add_signer(&env, signer);
    }

    pub fn remove_signer(env: Env, signer: Address) {
        env.current_contract_address().require_auth();
        Self::internal_remove_signer(&env, signer);
    }

    pub fn set_threshold(env: Env, threshold: u32) {
        env.current_contract_address().require_auth();
        Self::internal_set_threshold(&env, threshold);
    }

    // --- Internal Helpers ---

    fn internal_cancel(env: &Env, hash: Bytes) {
        let mut info: ProposalInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(hash.clone()))
            .unwrap_or_else(|| env.panic_with_error(Error::ProposalNotFound));

        if info.executed {
            env.panic_with_error(Error::AlreadyExecuted);
        }

        info.cancelled = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(hash.clone()), &info);

        env.events().publish((symbol_short!("cancelled"), hash), ());
    }

    fn internal_add_signer(env: &Env, signer: Address) {
        let mut signers: Vec<Address> = env.storage().instance().get(&DataKey::Signers).unwrap();
        if !signers.contains(&signer) {
            signers.push_back(signer);
            env.storage().instance().set(&DataKey::Signers, &signers);
        }
    }

    fn internal_remove_signer(env: &Env, signer: Address) {
        let mut signers: Vec<Address> = env.storage().instance().get(&DataKey::Signers).unwrap();
        let threshold: u32 = env.storage().instance().get(&DataKey::Threshold).unwrap();

        if let Some(idx) = signers.first_index_of(&signer) {
            if signers.len() <= threshold {
                env.panic_with_error(Error::InvalidThreshold);
            }
            signers.remove(idx);
            env.storage().instance().set(&DataKey::Signers, &signers);
        }
    }

    fn internal_set_threshold(env: &Env, threshold: u32) {
        let signers: Vec<Address> = env.storage().instance().get(&DataKey::Signers).unwrap();
        if threshold == 0 || threshold > signers.len() {
            env.panic_with_error(Error::InvalidThreshold);
        }
        env.storage()
            .instance()
            .set(&DataKey::Threshold, &threshold);
    }

    fn calculate_hash(
        env: &Env,
        target: &Address,
        function: &Symbol,
        args: &Vec<Val>,
        salt: &Bytes,
    ) -> Bytes {
        let mut data = Bytes::new(env);
        data.append(&target.clone().to_xdr(env));
        data.append(&function.clone().to_xdr(env));
        data.append(&args.clone().to_xdr(env));
        data.append(&salt.clone().to_xdr(env));

        env.crypto().sha256(&data).into()
    }
}
