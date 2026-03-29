#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, token, vec, xdr::ToXdr,
    Address, BytesN, Env, IntoVal, Symbol, Val, Vec,
};

#[cfg(test)]
mod test;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    Unauthorized = 3,
    ProposalNotFound = 4,
    InvalidState = 5,
    InvalidVote = 6,
    AlreadyVoted = 7,
    QuorumNotMet = 8,
    ProposalThresholdNotMet = 9,
}

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ProposalState {
    Pending = 0,
    Active = 1,
    Canceled = 2,
    Defeated = 3,
    Succeeded = 4,
    Queued = 5,
    Expired = 6,
    Executed = 7,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Config,              // GovernanceConfig
    Proposal(u32),       // u32 -> Proposal
    Votes(u32, Address), // (id, voter) -> bool
    LatestId,            // u32
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernanceConfig {
    pub token: Address,
    pub timelock: Address,
    pub quorum_bps: u32,          // in basis points (1/10000)
    pub threshold_bps: u32,       // majority required (e.g. 5001 for >50%)
    pub voting_period: u64,       // in seconds
    pub voting_delay: u64,        // in seconds
    pub proposal_threshold: i128, // min tokens to propose
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub id: u32,
    pub proposer: Address,
    pub targets: Vec<Address>,
    pub functions: Vec<Symbol>,
    pub args: Vec<Vec<Val>>,
    pub description: Symbol,
    pub start_time: u64,
    pub end_time: u64,
    pub for_votes: i128,
    pub against_votes: i128,
    pub abstain_votes: i128,
    pub executed: bool,
    pub canceled: bool,
    pub queued: bool,
}

#[contract]
pub struct GovernorContract;

#[contractimpl]
impl GovernorContract {
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        env: Env,
        token: Address,
        timelock: Address,
        quorum_bps: u32,
        threshold_bps: u32,
        voting_period: u64,
        voting_delay: u64,
        proposal_threshold: i128,
    ) {
        if env.storage().instance().has(&DataKey::Config) {
            env.panic_with_error(Error::AlreadyInitialized);
        }

        let config = GovernanceConfig {
            token,
            timelock,
            quorum_bps,
            threshold_bps,
            voting_period,
            voting_delay,
            proposal_threshold,
        };

        env.storage().instance().set(&DataKey::Config, &config);
        env.storage().instance().set(&DataKey::LatestId, &0u32);
    }

    pub fn propose(
        env: Env,
        proposer: Address,
        targets: Vec<Address>,
        functions: Vec<Symbol>,
        args: Vec<Vec<Val>>,
        description: Symbol,
    ) -> u32 {
        proposer.require_auth();

        let config: GovernanceConfig = env.storage().instance().get(&DataKey::Config).unwrap();

        let token_client = token::TokenClient::new(&env, &config.token);
        if token_client.balance(&proposer) < config.proposal_threshold {
            env.panic_with_error(Error::ProposalThresholdNotMet);
        }

        let id: u32 = env
            .storage()
            .instance()
            .get::<_, u32>(&DataKey::LatestId)
            .unwrap_or(0u32)
            + 1;
        env.storage().instance().set(&DataKey::LatestId, &id);

        let start_time = env.ledger().timestamp() + config.voting_delay;
        let end_time = start_time + config.voting_period;

        let proposal = Proposal {
            id,
            proposer: proposer.clone(),
            targets,
            functions,
            args,
            description,
            start_time,
            end_time,
            for_votes: 0,
            against_votes: 0,
            abstain_votes: 0,
            executed: false,
            canceled: false,
            queued: false,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);

        env.events()
            .publish((symbol_short!("proposed"), id), proposer);

        id
    }

    pub fn cast_vote(env: Env, voter: Address, proposal_id: u32, support: u32) -> i128 {
        voter.require_auth();

        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .unwrap_or_else(|| env.panic_with_error(Error::ProposalNotFound));

        let now = env.ledger().timestamp();
        if now < proposal.start_time || now > proposal.end_time {
            env.panic_with_error(Error::InvalidState);
        }

        let vote_key = DataKey::Votes(proposal_id, voter.clone());
        if env.storage().persistent().has(&vote_key) {
            env.panic_with_error(Error::AlreadyVoted);
        }

        let config: GovernanceConfig = env.storage().instance().get(&DataKey::Config).unwrap();
        let token_client = token::TokenClient::new(&env, &config.token);
        let weight = token_client.balance(&voter);

        if weight == 0 {
            env.panic_with_error(Error::Unauthorized);
        }

        match support {
            0 => proposal.against_votes += weight,
            1 => proposal.for_votes += weight,
            2 => proposal.abstain_votes += weight,
            _ => env.panic_with_error(Error::InvalidVote),
        }

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        env.storage().persistent().set(&vote_key, &true);

        env.events().publish(
            (symbol_short!("voted"), proposal_id, voter),
            (support, weight),
        );

        weight
    }

    pub fn queue(env: Env, proposal_id: u32) {
        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .unwrap_or_else(|| env.panic_with_error(Error::ProposalNotFound));

        if Self::state(env.clone(), proposal_id) != ProposalState::Succeeded {
            env.panic_with_error(Error::InvalidState);
        }

        proposal.queued = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);

        let config: GovernanceConfig = env.storage().instance().get(&DataKey::Config).unwrap();

        let salt = env
            .crypto()
            .sha256(&proposal.description.clone().to_xdr(&env));
        let salt_bytes = BytesN::from_array(&env, &salt.to_array());

        // Get min delay via raw invoke to avoid WASM import dependency in CI
        let min_delay: u64 = env.invoke_contract(
            &config.timelock,
            &Symbol::new(&env, "get_min_delay"),
            vec![&env],
        );

        for i in 0..proposal.targets.len() {
            let target = proposal.targets.get(i).unwrap();
            let function = proposal.functions.get(i).unwrap();
            let args = proposal.args.get(i).unwrap();

            let schedule_args: Vec<Val> = vec![
                &env,
                env.current_contract_address().into_val(&env),
                target.into_val(&env),
                function.into_val(&env),
                args.into_val(&env),
                salt_bytes.clone().into_val(&env),
                min_delay.into_val(&env),
            ];

            env.invoke_contract::<Val>(
                &config.timelock,
                &Symbol::new(&env, "schedule"),
                schedule_args,
            );
        }

        env.events()
            .publish((symbol_short!("queued"), proposal_id), ());
    }

    pub fn execute(env: Env, proposal_id: u32) {
        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .unwrap_or_else(|| env.panic_with_error(Error::ProposalNotFound));

        let state = Self::state(env.clone(), proposal_id);
        if proposal.executed || state != ProposalState::Queued {
            env.panic_with_error(Error::InvalidState);
        }

        let config: GovernanceConfig = env.storage().instance().get(&DataKey::Config).unwrap();
        let salt = env
            .crypto()
            .sha256(&proposal.description.clone().to_xdr(&env));
        let salt_bytes = BytesN::from_array(&env, &salt.to_array());

        for i in 0..proposal.targets.len() {
            let target = proposal.targets.get(i).unwrap();
            let function = proposal.functions.get(i).unwrap();
            let args = proposal.args.get(i).unwrap();

            let execute_args: Vec<Val> = vec![
                &env,
                env.current_contract_address().into_val(&env),
                target.into_val(&env),
                function.into_val(&env),
                args.into_val(&env),
                salt_bytes.clone().into_val(&env),
            ];

            env.invoke_contract::<Val>(
                &config.timelock,
                &Symbol::new(&env, "execute"),
                execute_args,
            );
        }

        proposal.executed = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);

        env.events()
            .publish((symbol_short!("executed"), proposal_id), ());
    }

    pub fn state(env: Env, proposal_id: u32) -> ProposalState {
        let proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .unwrap_or_else(|| env.panic_with_error(Error::ProposalNotFound));

        if proposal.canceled {
            return ProposalState::Canceled;
        }
        if proposal.executed {
            return ProposalState::Executed;
        }

        let now = env.ledger().timestamp();

        if now < proposal.start_time {
            return ProposalState::Pending;
        }

        if now <= proposal.end_time {
            return ProposalState::Active;
        }

        let config: GovernanceConfig = env.storage().instance().get(&DataKey::Config).unwrap();

        let total_supply: i128 = env.invoke_contract(
            &config.token,
            &Symbol::new(&env, "total_supply"),
            vec![&env],
        );
        let total_votes = proposal.for_votes + proposal.against_votes + proposal.abstain_votes;

        if (total_votes * 10000 / total_supply) < config.quorum_bps as i128 {
            return ProposalState::Defeated;
        }

        let support_votes = proposal.for_votes + proposal.against_votes;
        if support_votes == 0
            || (proposal.for_votes * 10000 / support_votes) < config.threshold_bps as i128
        {
            return ProposalState::Defeated;
        }

        if proposal.queued {
            return ProposalState::Queued;
        }

        ProposalState::Succeeded
    }
}
