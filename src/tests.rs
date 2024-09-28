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
    let user_setup = user.run_setup();
    let user2_setup = user2.run_setup();

    let (user_result, user2_result) = futures::join!(user_setup, user2_setup);

    user_result.unwrap();
    user2_result.unwrap();
}
