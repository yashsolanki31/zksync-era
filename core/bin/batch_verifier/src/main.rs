use anyhow::Context;
use tracing::{info, level_filters::LevelFilter};
use tracing_log::LogTracer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};
use zksync_config::{configs::object_store::ObjectStoreMode, ObjectStoreConfig};
use zksync_object_store::ObjectStoreFactory;
use zksync_tee_verifier::TeeVerifierInput;
use zksync_types::L1BatchNumber;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    LogTracer::init().context("Failed to set logger")?;

    let subscriber = Registry::default()
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with(fmt::layer().with_writer(std::io::stderr));
    tracing::subscriber::set_global_default(subscriber).context("Failed to set logger")?;

    let object_store = ObjectStoreFactory::new(ObjectStoreConfig {
        mode: ObjectStoreMode::FileBacked {
            file_backed_base_path: "artifacts".to_string(),
        },
        max_retries: 0,
    })
    .create_store()
    .await;

    for i in 1..u32::MAX {
        object_store
            .get::<TeeVerifierInput>(L1BatchNumber(i))
            .await
            .context(format!("failed to get batch verifier inputs for batch {i}"))?
            .run_tee_verifier()?;
        info!("Successfully validated batch {i}");
    }
    Ok(())
}
