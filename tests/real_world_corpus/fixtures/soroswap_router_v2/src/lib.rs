#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Env, String, Vec};

#[contracttype]
#[derive(Clone)]
pub struct RoutePath {
    pub steps: Vec<String>,
}

#[contract]
pub struct SoroswapRouterContract;

#[contractimpl]
impl SoroswapRouterContract {
    pub fn swap_exact_tokens(
        _env: Env,
        _amount_in: i128,
        _amount_out_min: i128,
        _path: RoutePath,
        _to: String,
    ) -> i128 {
        1000
    }
}
