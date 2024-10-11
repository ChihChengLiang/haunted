use haunted::worker;
use std::env;
use tokio::{signal, sync::broadcast};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    let server_uri = env::var("SERVER_URI").unwrap_or("ws://127.0.0.1:3000/worker/ws".to_string());
    let handle = tokio::spawn(worker::run(server_uri, shutdown_rx));

    if signal::ctrl_c().await.is_ok() {
        let _ = shutdown_tx.send(());
    }

    let _ = handle.await;
}
