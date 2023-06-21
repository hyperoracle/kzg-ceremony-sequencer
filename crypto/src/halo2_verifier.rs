use kzg_ceremony_prover::{serialization::BatchContribution, verify_proofs};
use std::fs;

pub fn verify_halo2_proofs(
    old_contributions: BatchContribution,
    new_contributions: BatchContribution,
    proofs: String,
) {
    let g1_params = fs::read("./crypto/g1_params.bin").expect("Read G1 params file failed");
    let g2_params = fs::read("./crypto/g2_params.bin").expect("Read G2 params file failed");

    verify_proofs(
        &old_contributions,
        &new_contributions,
        proofs,
        g1_params,
        g2_params,
    );
}
