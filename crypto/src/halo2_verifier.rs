use kzg_ceremony_circuit::K;
use kzg_ceremony_prover::{serialization::BatchContribution, verify_proofs};
use std::fs;

pub fn verify_halo2_proofs(
    old_contributions: BatchContribution,
    new_contributions: BatchContribution,
    proofs: String,
) {
    let params = fs::read(format!("./crypto/params_{}.bin", K)).expect("Read params file failed");

    verify_proofs(&old_contributions, &new_contributions, proofs, params);
}
