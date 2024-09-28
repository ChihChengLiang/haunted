use crate::client::Wallet;
use crate::server::rocket;

use std::time::Duration;
use tokio;
use tokio::sync::oneshot;

static N_USERS: usize = 2;

async fn setup_server(shutdown_rx: oneshot::Receiver<()>) {
    tokio::spawn(async move {
        rocket(N_USERS)
            .launch()
            .await
            .expect("server failed to start");
    });

    let _ = shutdown_rx.await;
}

#[rocket::async_test]
async fn test_fullflow() {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let server_handle = tokio::spawn(setup_server(shutdown_rx));

    // Give the server a moment to start up
    tokio::time::sleep(Duration::from_secs(1)).await;

    let url = "http://localhost:5566";
    let user = Wallet::new(url);
    let user2 = Wallet::new(url);
    let user_setup = user.run_setup();
    let user2_setup = user2.run_setup();

    let (user_result, user2_result) = futures::join!(user_setup, user2_setup);

    user_result.unwrap();
    user2_result.unwrap();

    // Signal the server to shut down
    shutdown_tx.send(()).unwrap();

    // Wait for the server to shut down
    server_handle.await.unwrap();
}
