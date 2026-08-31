#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Env, String};

#[contracttype]
#[derive(Clone)]
pub struct PriceData {
    pub price: i128,
    pub timestamp: u64,
}

#[contract]
pub struct ReflectorOracleContract;

#[contractimpl]
impl ReflectorOracleContract {
    pub fn lastprice(_env: Env, _symbol: String) -> PriceData {
        PriceData {
            price: 100_000_000,
            timestamp: 1700000000,
        }
    }
}
