use std::io;

use async_trait::async_trait;
use serde::Serialize;
use snarkify_sdk::prover::ProofHandler;
use std::env;

use axiom_eth::{
    halo2_base::{gates::circuit::CircuitBuilderStage, utils::fs::gen_srs},
    snark_verifier_sdk::{halo2::gen_snark_shplonk, CircuitExt},
    utils::{
        build_utils::pinning::PinnableCircuit,
        snark_verifier::{AggregationCircuitParams, EnhancedSnark, NUM_FE_ACCUMULATOR},
    },
};

use axiom_query::subquery_aggregation::types::{
    InputSubqueryAggregation, SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX,
};
use std::time::Instant;

struct MyProofHandler;

#[derive(Serialize)]
struct MyOutput {
    proof: String,
}

#[derive(Serialize)]
struct MyError {
    message: String,
}

impl From<anyhow::Error> for MyError {
    fn from(error: anyhow::Error) -> Self {
        MyError { message: error.to_string() }
    }
}

#[async_trait]
impl ProofHandler for MyProofHandler {
    type Input = InputSubqueryAggregation;
    type Output = MyOutput;
    type Error = MyError;

    async fn prove(input: Self::Input) -> Result<Self::Output, Self::Error> {
        let start = Instant::now();
        let service_data_dir = env::var("SERVICE_DATA_DIR").unwrap_or("/ramdisk".to_string());
        println!("path of service data: {}", service_data_dir);

        let k = 20;
        let params = gen_srs(k as u32);

        let mut keygen_circuit = input.clone().build(
            CircuitBuilderStage::Keygen,
            AggregationCircuitParams { degree: k as u32, lookup_bits: k - 1, ..Default::default() },
            &params,
        )?;
        keygen_circuit.calculate_params(Some(20));
        let instance1 = keygen_circuit.instances();
        let abs_agg_vk_hash_idx = SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX + NUM_FE_ACCUMULATOR;
        let name = "subquery_aggregation_for_agg";
        let pinning_path = format!("{service_data_dir}/configs/test/{name}.json");
        let pk_path = format!("{service_data_dir}/data/test/{name}.pk");
        let (pk, pinning) = keygen_circuit.create_pk(&params, pk_path, pinning_path)?;

        #[cfg(feature = "keygen")]
        {
            // test keygen
            use axiom_eth::halo2_proofs::{plonk::keygen_vk, SerdeFormat};
            use axiom_eth::snark_verifier_sdk::{halo2::gen_dummy_snark_from_protocol, SHPLONK};
            use axiom_eth::utils::build_utils::aggregation::get_dummy_aggregation_params;
            let [dum_snark_header, dum_snark_results] =
                [&input.snark_header, &input.snark_results_root].map(|s| {
                    EnhancedSnark::new(
                        gen_dummy_snark_from_protocol::<SHPLONK>(s.inner.protocol.clone()),
                        None,
                    )
                });
            let input = InputSubqueryAggregation {
                snark_header: dum_snark_header,
                snark_results_root: dum_snark_results,
                snark_account: None,
                snark_storage: None,
                snark_solidity_mapping: None,
                snark_tx: None,
                snark_receipt: None,
                promise_commit_keccak: Default::default(),
            };
            let mut circuit = input.build(
                CircuitBuilderStage::Keygen,
                get_dummy_aggregation_params(k),
                &params,
            )?;
            circuit.calculate_params(Some(20));
            let vk =
                keygen_vk(&params, &circuit).map_err(|e| MyError { message: e.to_string() })?;
            if pk.get_vk().to_bytes(SerdeFormat::RawBytes) != vk.to_bytes(SerdeFormat::RawBytes) {
                panic!("vk mismatch");
            }
            let instance2 = circuit.instances();
            assert_eq!(
                instance1[0][abs_agg_vk_hash_idx], instance2[0][abs_agg_vk_hash_idx],
                "agg vkey hash mismatch"
            );
        }

        let mut prover_circuit =
            input.build(CircuitBuilderStage::Prover, pinning.params, &params)?;
        prover_circuit.set_break_points(pinning.break_points);

        let snark = gen_snark_shplonk(&params, &pk, prover_circuit, None::<&str>);
        let instance3 = snark.instances.clone();
        let snark = EnhancedSnark {
            inner: snark,
            agg_vk_hash_idx: Some(SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX),
        };
        assert_eq!(
            instance1[0][abs_agg_vk_hash_idx], instance3[0][abs_agg_vk_hash_idx],
            "agg vkey hash mismatch"
        );

        let duration = start.elapsed();
        println!("Time elapsed is: {:?}", duration);
        Ok(MyOutput { proof: serde_json::to_string(&snark).unwrap() })
    }
}

fn main() -> Result<(), io::Error> {
    snarkify_sdk::run::<MyProofHandler>()
}
