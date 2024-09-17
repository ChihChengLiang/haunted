use crate::client::{Request, Wallet};
use anyhow::{anyhow, bail, Error};
use rocket::{
    local::asynchronous::{Client, LocalResponse},
    Build, Rocket,
};
use serde::Deserialize;

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
