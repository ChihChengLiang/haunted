use crate::{
    client::Client,
    server::test::{test_server, TEST_PARAM},
    user::User,
    worker,
};
use futures_util::{
    future::{join_all, try_join_all},
    FutureExt, TryFuture, TryFutureExt,
};
use itertools::{chain, Itertools};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{spawn, sync::broadcast, time::sleep};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::test]
async fn e2e() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(LevelFilter::INFO.into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let (server_handle, server_addr) = test_server().await;

    tracing::info!("server listening on on {server_addr}");

    let (shutdown_tx, _) = broadcast::channel(4);
    let worker_handles = (0..TEST_PARAM.total_shares)
        .map(|_| {
            let shutdown_rx = shutdown_tx.subscribe();
            spawn(worker::run(format!("ws://{server_addr}/ws"), shutdown_rx))
        })
        .collect_vec();

    tracing::info!("{} workers connected to server", worker_handles.len());

    let client = &Client::new(format!("http://{server_addr}"));
    let users = (0..TEST_PARAM.total_shares)
        .map(|user_id| async move {
            User::new(client.clone(), user_id, StdRng::from_entropy().gen())
                .await
                .map(Arc::new)
        })
        .try_join_vec()
        .await
        .unwrap();

    tracing::info!("{} users participating key generation", users.len());

    users
        .iter()
        .try_join_for_each(|user| user.participate_key_gen())
        .await
        .unwrap();
    users
        .iter()
        .try_join_for_each(|user| user.wait_until_game_ready())
        .await
        .unwrap();

    tracing::info!("key generation finished");

    tracing::info!("users participating decryption continuously");

    let user_decryption_handles = users
        .clone()
        .into_iter()
        .map(|user| tokio::spawn(async move { user.participate_decryption().await.unwrap() }))
        .collect_vec();

    sleep(Duration::from_secs(1)).await;

    let print_decryptable = || async {
        tracing::info!("users getting decryptable and decrypt");

        users
            .iter()
            .join_for_each(|user| async {
                assert!(client
                    .get_user_tasks(user.user_id())
                    .await
                    .unwrap()
                    .tasks
                    .is_empty());
                let decrypted = user
                    .get_decryptables()
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|decryptable| {
                        user.decrypt(&decryptable)
                            .into_iter()
                            .map(|bit| format!("{}", bit as usize))
                            .join("")
                    })
                    .collect_vec();
                tracing::info!("user {} got {decrypted:?}", user.user_id())
            })
            .await;
    };

    print_decryptable().await;

    tracing::info!("users submit their action (for demo it flips the designated decryptable)",);

    users
        .iter()
        .try_join_for_each(|user| user.demo([true; 10]))
        .await
        .unwrap();

    sleep(Duration::from_secs(1)).await;

    print_decryptable().await;

    shutdown_tx.send(()).unwrap();
    try_join_all(worker_handles).await.unwrap();

    chain![user_decryption_handles, [server_handle]]
        .join_for_each(|handle| async {
            handle.abort();
            assert!(handle.await.unwrap_err().is_cancelled());
        })
        .await;
}

pub trait ItertoolsExt: Itertools {
    fn try_join_vec(
        self,
    ) -> impl Future<Output = Result<Vec<<Self::Item as TryFuture>::Ok>, <Self::Item as TryFuture>::Error>>
    where
        Self: Sized,
        Self::Item: TryFuture,
    {
        try_join_all(self)
    }

    fn join_for_each<F: Future>(self, f: impl Fn(Self::Item) -> F) -> impl Future<Output = ()>
    where
        Self: Sized,
    {
        join_all(self.map(f)).map(|_| ())
    }

    fn try_join_for_each<F: TryFuture>(
        self,
        f: impl Fn(Self::Item) -> F,
    ) -> impl Future<Output = Result<(), F::Error>>
    where
        Self: Sized,
    {
        try_join_all(self.map(f)).map_ok(|_| ())
    }
}

impl<I: Itertools> ItertoolsExt for I {}
