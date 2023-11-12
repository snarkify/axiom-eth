#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};
use axiom_eth::{
    block_header::helpers::{BlockHeaderScheduler, CircuitType, Finality, Task},
    util::scheduler::Scheduler,
    Network,
};
use std::{cmp::min, fs, path::PathBuf, thread};
use std::sync::mpsc;
use base64::{engine::general_purpose::STANDARD as BS64, Engine};
use serde::{Deserialize, Serialize};
use snarkify_sdk::prover::ProofHandler;
use reqwest::blocking::Response;
use std::io::Write;
use std::path::Path;

fn download_file(url: &str, output_path: &str) {
    // Send a GET request to the specified URL
    let response: Response = reqwest::blocking::get(url).expect("Download Failed");

    // Check if the request was successful
    if response.status().is_success() {
        let path = Path::new(output_path);
        if path.is_file() {
            return
        }

        if let Some(dir_path) = path.parent() {
            fs::create_dir_all(dir_path).expect("Create dir Failed");
        }
        let mut file = fs::File::create(output_path).expect("Create file Failed");

        // Write the response body to the file
        file.write_all(response.bytes().unwrap().as_ref()).expect("Save Failed");
    } else {
        panic!("Download failed!")
    }
}


#[derive(Deserialize)]
pub struct Input {
    start_block_num: u32,
    end_block_num: u32,
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
        assert!(input.end_block_num >= input.start_block_num, "end_block_num can't be less than start_block_num!");
        assert!(input.end_block_num < input.start_block_num + 4, "end_block_num has to be within 4 blocks of start_block_num!");
        let start_block_number = input.start_block_num;
        let end_block_number = input.end_block_num;
        let initial_depth = 2;
        let max_depth = initial_depth;
        let network = Network::Goerli;
        let srs_readonly = true;

        thread::spawn(|| {
            download_file("https://github.com/snarkify/axiom-eth/raw/snarkify/params/kzg_bn254_15.srs",
              "params/kzg_bn254_15.srs");
            println!("Params file downloaded!");
        }).join().expect("Download failed!");
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
        let (tx, rx) = mpsc::channel();
        for start in (start_block_number..=end_block_number).step_by(1 << max_depth) {
            let end = min(start + (1 << max_depth) - 1, end_block_number);
            let task = Task::new(start, end, circuit_type);
            let tx_clone = tx.clone();
            thread::spawn(move || {
                let scheduler = BlockHeaderScheduler::new(
                    network,
                    srs_readonly,
                    false,
                    PathBuf::from("configs/headers"),
                    PathBuf::from("data/headers"),
                );

                let snark = scheduler.get_snark(task);
                let encoded_proof = BS64.encode(snark.proof);
                tx_clone.send(encoded_proof).expect("Failed to send data");
            }).join().expect("Unexpected failure!");
        }

        let proof = rx.recv().unwrap();
        #[cfg(feature = "display")]
        end_timer!(start);
        Ok(Output {proof})
    }
}

fn main() -> Result<(), std::io::Error> {
    snarkify_sdk::run::<BlockHeaderProver>()
}
