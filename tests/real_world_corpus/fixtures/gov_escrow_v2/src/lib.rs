#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Env, String};

#[contracttype]
#[derive(Clone)]
pub struct Proposal {
    pub id: u32,
    pub title: String,
}

#[contract]
pub struct GovEscrowContract;

#[contractimpl]
impl GovEscrowContract {
    pub fn vote(_env: Env, _proposal_id: u32, _support: bool, _weight: i128) {
        // cast weighted vote
    }
}
