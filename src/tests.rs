use std::time::Duration;

use crate::client::{ProductionClient, Request, Wallet};
use crate::server::rocket;
use anyhow::{anyhow, bail, Error};
use rocket::{
    local::asynchronous::{Client, LocalResponse},
    Build, Rocket,
};
use serde::Deserialize;
use tokio::time::sleep;

impl Wallet<TestClient> {
    async fn new_test(rocket: Rocket<Build>) -> Result<Self, Error> {
        let client = Client::tracked(rocket).await?;
        Ok(Self {
            rc: TestClient(client),
        })
    }
}

#[derive(Debug)]
struct TestClient(Client);

async fn handle_response<T: Send + for<'de> Deserialize<'de> + 'static>(
    response: LocalResponse<'_>,
) -> Result<T, Error> {
    match response.status().code {
        200 => response
            .into_json::<T>()
            .await
            .ok_or(anyhow!("Can't parse response output")),
        _ => {
            let err = response
                .into_string()
                .await
                .ok_or(anyhow!("Can't parse response output"))?;
            bail!("Server responded error: {:?}", err)
        }
    }
}

impl Request for TestClient {
    fn get<T: Send + for<'de> serde::Deserialize<'de> + 'static>(
        &self,
        path: &str,
    ) -> impl std::future::Future<Output = Result<T, anyhow::Error>> {
        async move {
            let response = self.0.get(path).dispatch().await;
            handle_response(response).await
        }
    }

    fn post_nobody<T: Send + for<'de> serde::Deserialize<'de> + 'static>(
        &self,
        path: &str,
    ) -> impl std::future::Future<Output = Result<T, anyhow::Error>> {
        async move {
            let response = self.0.post(path).dispatch().await;
            handle_response(response).await
        }
    }

    fn post<T: Send + for<'de> serde::Deserialize<'de> + 'static>(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<T, anyhow::Error>> {
        async move {
            let response = self.0.post(path).body(body).dispatch().await;
            handle_response(response).await
        }
    }

    fn post_msgpack<T: Send + for<'de> serde::Deserialize<'de> + 'static>(
        &self,
        path: &str,
        body: &impl serde::Serialize,
    ) -> impl std::future::Future<Output = Result<T, anyhow::Error>> {
        async move {
            let response = self.0.post(path).msgpack(body).dispatch().await;
            handle_response(response).await
        }
    }
}

use std::sync::Once;
use tokio;

static INIT: Once = Once::new();

async fn setup_server() {
    INIT.call_once(|| {
        tokio::spawn(async {
            rocket().launch().await.expect("server failed to start");
        });
    });
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
}

#[rocket::async_test]
async fn test_fullflow() {
    setup_server().await;
    let url = "http://localhost:5566";
    let user = Wallet::<ProductionClient>::new(url);
    let user2 = Wallet::<ProductionClient>::new(url);
    user.run_setup().await.unwrap();
    user2.run_setup().await.unwrap();
   
}
