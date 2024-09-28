use crate::client::Wallet;
use crate::server::rocket;

use std::sync::Once;
use tokio;

static INIT: Once = Once::new();
static N_USERS: usize = 2;

async fn setup_server() {
    INIT.call_once(|| {
        tokio::spawn(async {
            rocket(N_USERS)
                .launch()
                .await
                .expect("server failed to start");
        });
    });
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
}

#[rocket::async_test]
async fn test_fullflow() {
    setup_server().await;
    let url = "http://localhost:5566";
    let user = Wallet::new(url);
    let user2 = Wallet::new(url);
    user.run_setup().await.unwrap();
    user2.run_setup().await.unwrap();
}
