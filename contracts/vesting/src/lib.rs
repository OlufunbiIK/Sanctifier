#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, token, Address, Env,
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
    NoVestedTokens = 4,
    AlreadyRevoked = 5,
    NotRevocable = 6,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Admin,
    Beneficiary,
    Token,
    Start,
    Cliff,
    Duration,
    TotalAmount,
    Released,
    Revocable,
    Revoked,
}

#[contract]
pub struct VestingContract;

#[contractimpl]
impl VestingContract {
    /// Initialize the vesting schedule.
    /// @param admin The address that can revoke the vesting.
    /// @param beneficiary The address that will receive the vested tokens.
    /// @param token The token address (SAC).
    /// @param start The start timestamp of the vesting.
    /// @param cliff The cliff duration in seconds.
    /// @param duration The total duration of the vesting in seconds.
    /// @param amount The total amount of tokens to vest.
    /// @param revocable Whether the admin can revoke the vesting.
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        env: Env,
        admin: Address,
        beneficiary: Address,
        token: Address,
        start: u64,
        cliff: u64,
        duration: u64,
        amount: i128,
        revocable: bool,
    ) {
        if env.storage().instance().has(&DataKey::Admin) {
            env.panic_with_error(Error::AlreadyInitialized);
        }

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::Beneficiary, &beneficiary);
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage().instance().set(&DataKey::Start, &start);
        env.storage().instance().set(&DataKey::Cliff, &cliff);
        env.storage().instance().set(&DataKey::Duration, &duration);
        env.storage().instance().set(&DataKey::TotalAmount, &amount);
        env.storage().instance().set(&DataKey::Released, &0i128);
        env.storage()
            .instance()
            .set(&DataKey::Revocable, &revocable);
        env.storage().instance().set(&DataKey::Revoked, &false);

        // Transfer funds from admin to the contract.
        // Admin must provide authorization for 'init'.
        admin.require_auth();
        let client = token::Client::new(&env, &token);
        client.transfer(&admin, &env.current_contract_address(), &amount);
    }

    /// Claim currently vested tokens.
    pub fn claim(env: Env) -> i128 {
        let beneficiary: Address = env.storage().instance().get(&DataKey::Beneficiary).unwrap();
        beneficiary.require_auth();

        let total_vested = Self::vested_amount(env.clone());
        let released: i128 = env.storage().instance().get(&DataKey::Released).unwrap();
        let claimable = total_vested - released;

        if claimable <= 0 {
            env.panic_with_error(Error::NoVestedTokens);
        }

        let new_released = released + claimable;
        env.storage()
            .instance()
            .set(&DataKey::Released, &new_released);

        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &beneficiary, &claimable);

        env.events()
            .publish((symbol_short!("claimed"), beneficiary), claimable);

        claimable
    }

    /// Revoke the vesting schedule.
    /// This stops future vesting and returns unvested tokens to the admin.
    pub fn revoke(env: Env) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        let revocable: bool = env.storage().instance().get(&DataKey::Revocable).unwrap();
        if !revocable {
            env.panic_with_error(Error::NotRevocable);
        }

        let revoked: bool = env.storage().instance().get(&DataKey::Revoked).unwrap();
        if revoked {
            env.panic_with_error(Error::AlreadyRevoked);
        }

        // Calculation: what is vested now is the final limit.
        let total_vested = Self::vested_amount(env.clone());
        let total_amount: i128 = env.storage().instance().get(&DataKey::TotalAmount).unwrap();
        let unvested = total_amount - total_vested;

        env.storage().instance().set(&DataKey::Revoked, &true);
        env.storage()
            .instance()
            .set(&DataKey::TotalAmount, &total_vested);

        if unvested > 0 {
            let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
            let client = token::Client::new(&env, &token);
            client.transfer(&env.current_contract_address(), &admin, &unvested);
        }

        env.events()
            .publish((symbol_short!("revoked"), admin), unvested);
    }

    /// View total vested amount (regardless of how much was already claimed).
    pub fn vested_amount(env: Env) -> i128 {
        let revoked: bool = env
            .storage()
            .instance()
            .get(&DataKey::Revoked)
            .unwrap_or(false);
        let total_amount: i128 = env.storage().instance().get(&DataKey::TotalAmount).unwrap();

        if revoked {
            return total_amount;
        }

        let start: u64 = env.storage().instance().get(&DataKey::Start).unwrap();
        let cliff: u64 = env.storage().instance().get(&DataKey::Cliff).unwrap();
        let duration: u64 = env.storage().instance().get(&DataKey::Duration).unwrap();
        let now = env.ledger().timestamp();

        if now < start + cliff {
            0
        } else if now >= start + duration {
            total_amount
        } else {
            // Linear vesting calculation: amount * (now - start) / duration
            // Use i128 for all calculations to prevent precision loss.
            let elapsed = (now - start) as i128;
            let total_dur = duration as i128;

            // vested = (amount * elapsed) / total_dur
            total_amount * elapsed / total_dur
        }
    }

    pub fn claimable_amount(env: Env) -> i128 {
        let vested = Self::vested_amount(env.clone());
        let released: i128 = env
            .storage()
            .instance()
            .get(&DataKey::Released)
            .unwrap_or(0);
        vested - released
    }

    pub fn get_beneficiary(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Beneficiary).unwrap()
    }
}
