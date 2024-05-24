CREATE TABLE IF NOT EXISTS tee_proof_generation_details
(
    l1_batch_number         BIGINT PRIMARY KEY REFERENCES tee_verifier_input_producer_jobs (l1_batch_number) ON DELETE CASCADE,
    status                  TEXT      NOT NULL,
    signature               TEXT,
    pubkey                  TEXT,
    attestation             TEXT,
    tee_type                TEXT,
    created_at              TIMESTAMP NOT NULL,
    updated_at              TIMESTAMP NOT NULL,
    prover_taken_at         TIMESTAMP
);


CREATE INDEX IF NOT EXISTS idx_tee_proof_generation_details_status_prover_taken_at
    ON tee_proof_generation_details (prover_taken_at)
    WHERE status = 'picked_by_prover';
