use crate::{
    api::v1::contribute::{ContributeError, ContributeReceipt},
    io::write_json_file,
    keys::SharedKeys,
    lobby::SharedLobbyState,
    receipt::Receipt,
    storage::PersistentStorage,
    Engine, Options, SessionId, SharedCeremonyStatus, SharedTranscript,
};
use axum::{Extension, Json};
use kzg_ceremony_crypto::BatchContribution;
use std::sync::atomic::Ordering;
use tracing::{error, info};

use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BatchContributionWithProofs {
    pub contributions: BatchContribution,
    pub proofs:        String,
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "halo2")]
pub async fn contribute_with_halo2(
    session_id: SessionId,
    Json(bc_with_proofs): Json<BatchContributionWithProofs>,
    Extension(lobby_state): Extension<SharedLobbyState>,
    Extension(options): Extension<Options>,
    Extension(shared_transcript): Extension<SharedTranscript>,
    Extension(storage): Extension<PersistentStorage>,
    Extension(num_contributions): Extension<SharedCeremonyStatus>,
    Extension(keys): Extension<SharedKeys>,
) -> Result<ContributeReceipt, ContributeError> {
    // Handle the contribution in the background, so that request cancelation
    // doesn't interrupt it.
    let contribution = bc_with_proofs.contributions;
    let proofs = bc_with_proofs.proofs;
    info!("contribute with halo2");
    let res = tokio::spawn(async move {
        let id_token = lobby_state
            .begin_contributing(&session_id)
            .await
            .map_err(|_| ContributeError::NotUsersTurn)?
            .token;

        let result = {
            let mut transcript = shared_transcript.write().await;
            transcript
                .verify_halo2_add::<Engine>(contribution.clone(), proofs, id_token.identity.clone())
                .map_err(ContributeError::InvalidContribution)
        };

        if let Err(e) = result {
            lobby_state.clear_current_contributor().await;
            storage
                .expire_contribution(&id_token.unique_identifier())
                .await?;
            return Err(e);
        }

        let result = write_json_file(
            options.transcript_file,
            options.transcript_in_progress_file,
            shared_transcript,
        )
        .await;

        lobby_state.clear_current_contributor().await;
        storage.finish_contribution(&session_id.0).await?;

        if let Err(e) = result {
            error!("failed to write transcript: {}", e);
            return Err(ContributeError::TranscriptIOError(e));
        }

        num_contributions.fetch_add(1, Ordering::Relaxed);

        let receipt = Receipt {
            identity: id_token.identity,
            witness:  contribution.receipt(),
        };

        let (signed_msg, signature) = receipt
            .sign(&keys)
            .await
            .map_err(ContributeError::ReceiptSigning)?;

        Ok(ContributeReceipt {
            receipt: signed_msg,
            signature,
        })
    })
    .await
    .unwrap_or_else(|e| Err(ContributeError::TaskError(e)));
    if let Err(err) = &res {
        if matches!(
            err,
            ContributeError::ReceiptSigning(_)
                | ContributeError::StorageError(_)
                | ContributeError::TaskError(_)
        ) {
            error!(?err, "unexpected error recording contribution");
        }
    }
    res
}
