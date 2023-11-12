#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};
use axiom_eth::{
    block_header::helpers::{BlockHeaderScheduler, CircuitType, Finality, Task},
    util::scheduler::Scheduler,
    Network,
};
use std::{cmp::min, path::PathBuf};
use base64::{engine::general_purpose::STANDARD as BS64, Engine};
use serde::{Deserialize, Serialize};
use snarkify_sdk::prover::ProofHandler;


#[derive(Deserialize)]
pub struct Input {
    block_num: u32,
}

#[derive(Serialize)]
pub struct Output {
    proof: String
}

struct BlockHeaderProver;

impl ProofHandler for BlockHeaderProver {
    type Input = Input;
    type Output = Output;
    type Error = ();

    fn prove(input: Self::Input) -> Result<Self::Output, Self::Error> {
        let start_block_number = input.block_num;
        let end_block_number = start_block_number;
        let initial_depth = 2;
        let max_depth = initial_depth;
        let network = Network::Goerli;
        let srs_readonly = true;

        let scheduler = BlockHeaderScheduler::new(
            network,
            srs_readonly,
            false,
            PathBuf::from("configs/headers"),
            PathBuf::from("data/headers"),
        );

        #[cfg(feature = "display")]
        let start = start_timer!(|| format!(
            "Generating SNARKs for blocks {} to {}, max depth {}, initial depth {}, finality {}",
            start_block_number,
            end_block_number,
            max_depth,
            initial_depth,
            "none"
        ));

        let circuit_type = CircuitType::new(max_depth, initial_depth, Finality::None, network);
        let mut snark;
        let mut encoded_proof = "".to_string();
        for start in (start_block_number..=end_block_number).step_by(1 << max_depth) {
            let end = min(start + (1 << max_depth) - 1, end_block_number);
            let task = Task::new(start, end, circuit_type);
            snark = scheduler.get_snark(task);
            encoded_proof = BS64.encode(snark.proof);
        }

        #[cfg(feature = "display")]
        end_timer!(start);
        Ok(Output {proof: encoded_proof})
    }
}

fn main() -> Result<(), std::io::Error> {
    snarkify_sdk::run::<BlockHeaderProver>()
}
