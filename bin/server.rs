use haunted::{
    phantom::{PhantomCrs, PhantomParam},
    server::{self, ServerState},
};
use std::env;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let server_addr = env::var("SERVER_ADDR").unwrap_or("127.0.0.1:3000".to_string());
    let listener = TcpListener::bind(&server_addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    let state = ServerState::new(PhantomParam::I_4P_60, PhantomCrs::from_entropy());
    let router = server::router(state);
    axum::serve(listener, router).await.unwrap();
}
