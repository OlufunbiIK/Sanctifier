use crate::{TimelockController, TimelockControllerClient};
use soroban_sdk::{
    contract, contractimpl, testutils::Address as _, testutils::Ledger as _, Address, BytesN, Env,
    IntoVal, Symbol, Val, Vec,
};

#[contract]
pub struct MockContract;

#[contractimpl]
impl MockContract {
    pub fn action(_env: Env, value: u32) -> u32 {
        value + 1
    }
}

#[test]
fn test_timelock_flow() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let proposer = Address::generate(&env);
    let executor = Address::generate(&env);

    let timelock_id = env.register_contract(None, TimelockController);
    let timelock = TimelockControllerClient::new(&env, &timelock_id);

    let proposers = Vec::from_array(&env, [proposer.clone()]);
    let executors = Vec::from_array(&env, [executor.clone()]);
    let min_delay = 3600; // 1 hour

    timelock.init(&admin, &min_delay, &proposers, &executors);

    let mock_id = env.register_contract(None, MockContract);
    let fn_name = Symbol::new(&env, "action");
    let args = Vec::from_array(&env, [10u32.into_val(&env)]);
    let salt = BytesN::from_array(&env, &[0u8; 32]);

    // Schedule
    let delay = 3600;
    let _hash = timelock.schedule(&proposer, &mock_id, &fn_name, &args, &salt, &delay);

    // Fast forward time
    env.ledger().with_mut(|li| {
        li.timestamp += 3601;
    });

    // Execute
    let result: Val = timelock.execute(&executor, &mock_id, &fn_name, &args, &salt);
    let result_u32: u32 = result.into_val(&env);
    assert_eq!(result_u32, 11u32);
}

#[test]
fn test_role_management() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let proposer = Address::generate(&env);
    let timelock_id = env.register_contract(None, TimelockController);
    let timelock = TimelockControllerClient::new(&env, &timelock_id);

    timelock.init(&admin, &3600, &Vec::new(&env), &Vec::new(&env));

    assert!(!timelock.is_proposer(&proposer));
    timelock.set_proposer(&admin, &proposer, &true);
    assert!(timelock.is_proposer(&proposer));
    timelock.set_proposer(&admin, &proposer, &false);
    assert!(!timelock.is_proposer(&proposer));
}

#[test]
fn test_update_delay() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let timelock_id = env.register_contract(None, TimelockController);
    let timelock = TimelockControllerClient::new(&env, &timelock_id);

    timelock.init(&admin, &3600, &Vec::new(&env), &Vec::new(&env));
    assert_eq!(timelock.get_min_delay(), 3600);

    timelock.update_delay(&admin, &7200);
    assert_eq!(timelock.get_min_delay(), 7200);
}
