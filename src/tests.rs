use crate::client::Wallet;
use crate::server::rocket;
use crate::types::TaskStatus;

use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tokio::time::{sleep, Duration};

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
    sleep(Duration::from_secs(1)).await;

    let url = "http://localhost:5566";
    let user1 = Wallet::new(url);
    let user2 = Wallet::new(url);
    let user1_setup = user1.run_setup();
    let user2_setup = user2.run_setup();

    let (user1, user2) = futures::join!(user1_setup, user2_setup);

    let user1 = Arc::new(Mutex::new(user1.unwrap()));
    let user2 = Arc::new(Mutex::new(user2.unwrap()));

    // Start background tasks for both users
    let user1_clone = Arc::clone(&user1);
    let user2_clone = Arc::clone(&user2);
    let user1_handle = tokio::spawn(async move {
        user1_clone
            .lock()
            .await
            .run_background_tasks()
            .await
            .unwrap();
    });
    let user2_handle = tokio::spawn(async move {
        user2_clone
            .lock()
            .await
            .run_background_tasks()
            .await
            .unwrap();
    });

    // User1 initiates a task
    let task_id = {
        let mut user1 = user1.lock().await;
        user1
            .create_task(vec![user2.lock().await.user_id], vec![true, false])
            .await
            .unwrap()
    };

    // Wait for both users to decrypt the outputs
    let mut decrypted = false;
    while !decrypted {
        sleep(Duration::from_secs(1)).await;
        let user1_tasks = user1.lock().await;
        let user2_tasks = user2.lock().await;

        if let Some(status) = user1_tasks.get_task(&task_id) {
            if *status == TaskStatus::Done {
                decrypted = true;
                break;
            }
        }

        if let Some(status) = user2_tasks.get_task(&task_id) {
            if *status == TaskStatus::Done {
                decrypted = true;
                break;
            }
        }
    }

    // Signal the server to shut down
    shutdown_tx.send(()).unwrap();

    // Wait for the server to shut down
    server_handle.await.unwrap();

    // Stop background tasks
    user1_handle.abort();
    user2_handle.abort();

    // Final assertions
    let user1 = user1.lock().await;
    let user2 = user2.lock().await;
    assert_eq!(user1.get_task(&task_id), Some(&TaskStatus::Done));
    assert_eq!(user2.get_task(&task_id), Some(&TaskStatus::Done));
}
