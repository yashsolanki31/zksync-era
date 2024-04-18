use anyhow::Context;
use zksync_basic_types::L1BatchNumber;
use zksync_config::{configs::object_store::ObjectStoreMode, ObjectStoreConfig};
use zksync_object_store::ObjectStoreFactory;
use zksync_tee_verifier::TeeVerifierInput;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let object_store = ObjectStoreFactory::new(ObjectStoreConfig {
        mode: ObjectStoreMode::FileBacked {
            file_backed_base_path: "artifacts".to_string(),
        },
        max_retries: 0,
    })
    .create_store()
    .await;

    let v = object_store
        .get::<TeeVerifierInput>(L1BatchNumber(1))
        .await
        .context("failed to get batch verifier inputs")?;

    println!("{v:#?}");
    Ok(())
}
