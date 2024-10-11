use crate::{
    phantom::{PhantomBsKeyShare, PhantomPackedCtDecShare, PhantomPkShare, PhantomRpKeyShare},
    server::app::{
        Action, CreateUserActionRequest, CreateUserActionResponse, CreateUserBsKeyShareRequest,
        CreateUserBsKeyShareResponse, CreateUserPkShareRequest, CreateUserPkShareResponse,
        CreateUserRpKeyShareRequest, CreateUserRpKeyShareResponse, GetPkResponse, GetSetupResponse,
        GetStatusResponse, GetUserDecryptablesResponse, GetUserTasksResponse, Task,
        UpdateUserTasksRequest, UserId,
    },
    Result,
};
use anyhow::{anyhow, bail};
use axum::body::Body;
use core::future::Future;
use futures_util::TryFutureExt;
use http_body_util::BodyExt;
use hyper::{Request, Response, StatusCode};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client as HyperUtilClient},
    rt::TokioExecutor,
};
use serde::{de::DeserializeOwned, Serialize};

pub trait HttpClient {
    type Body: BodyExt<Error: std::error::Error>;

    fn request(&self, req: Request<Body>) -> impl Future<Output = Result<Response<Self::Body>>>;
}

impl HttpClient for HyperUtilClient<HttpConnector, Body> {
    type Body = hyper::body::Incoming;

    fn request(&self, req: Request<Body>) -> impl Future<Output = Result<Response<Self::Body>>> {
        self.request(req)
            .map_err(|err| anyhow!("failed to send request, {err}"))
    }
}

#[derive(Clone)]
pub struct Client<T = HyperUtilClient<HttpConnector, Body>> {
    uri: String,
    inner: T,
}

impl Client {
    pub fn new(uri: impl ToString) -> Self {
        let uri = uri.to_string();
        let inner = HyperUtilClient::builder(TokioExecutor::new()).build(HttpConnector::new());
        Self { uri, inner }
    }
}

impl<H: HttpClient> Client<H> {
    async fn call<T: DeserializeOwned>(&self, request: Request<Body>) -> Result<T> {
        let (method, uri) = (request.method().clone(), request.uri().clone());
        tracing::debug!("send {method} {uri}");
        let response = self.inner.request(request).await?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|err| anyhow!("failed to collect body, {err}"))?;
        if !matches!(status, StatusCode::OK) {
            let bytes = body.to_bytes();
            let msg = String::from_utf8_lossy(&bytes);
            bail!("failed to {method} {uri}, {msg}",)
        }
        Ok(bincode::deserialize(&body.to_bytes())?)
    }

    async fn get<T: DeserializeOwned>(&self, path: impl AsRef<str>) -> Result<T> {
        let uri = format!("{}{}", &self.uri, path.as_ref());
        let request = Request::get(&uri).body(Body::empty()).unwrap();
        self.call(request).await
    }

    async fn post<U: Serialize, T: DeserializeOwned>(
        &self,
        path: impl AsRef<str>,
        body: &U,
    ) -> Result<T> {
        let uri = format!("{}{}", &self.uri, path.as_ref());
        let body = bincode::serialize(body)?;
        let request = Request::post(&uri).body(Body::from(body)).unwrap();
        self.call(request).await
    }

    async fn put<U: Serialize, T: DeserializeOwned>(
        &self,
        path: impl AsRef<str>,
        body: &U,
    ) -> Result<T> {
        let uri = format!("{}{}", &self.uri, path.as_ref());
        let body = bincode::serialize(body)?;
        let request = Request::put(&uri).body(Body::from(body)).unwrap();
        self.call(request).await
    }

    pub async fn get_status(&self) -> Result<GetStatusResponse> {
        self.get("/status").await
    }

    pub async fn get_setup(&self) -> Result<GetSetupResponse> {
        self.get("/setup").await
    }

    pub async fn get_pk(&self) -> Result<GetPkResponse> {
        self.get("/pk").await
    }

    pub async fn create_user_pk_share(
        &self,
        user_id: UserId,
        pk_share: PhantomPkShare,
    ) -> Result<CreateUserPkShareResponse> {
        self.post(
            format!("/users/{user_id}/pk_share"),
            &CreateUserPkShareRequest { pk_share },
        )
        .await
    }

    pub async fn create_user_rp_key_share(
        &self,
        user_id: UserId,
        rp_key_share: PhantomRpKeyShare,
    ) -> Result<CreateUserRpKeyShareResponse> {
        self.post(
            format!("/users/{user_id}/rp_key_share"),
            &CreateUserRpKeyShareRequest { rp_key_share },
        )
        .await
    }

    pub async fn create_user_bs_key_share(
        &self,
        user_id: UserId,
        bs_key_share: PhantomBsKeyShare,
    ) -> Result<CreateUserBsKeyShareResponse> {
        self.post(
            format!("/users/{user_id}/bs_key_share"),
            &CreateUserBsKeyShareRequest { bs_key_share },
        )
        .await
    }

    pub async fn get_user_decryptables(
        &self,
        user_id: UserId,
    ) -> Result<GetUserDecryptablesResponse> {
        self.get(format!("/users/{user_id}/decryptables")).await
    }

    pub async fn get_user_tasks(&self, user_id: UserId) -> Result<GetUserTasksResponse> {
        self.get(format!("/users/{user_id}/tasks")).await
    }

    pub async fn create_decryption_share(
        &self,
        user_id: UserId,
        dec_shares: Vec<(usize, PhantomPackedCtDecShare)>,
    ) -> Result<()> {
        self.put(
            format!("/users/{user_id}/tasks"),
            &UpdateUserTasksRequest {
                tasks: dec_shares
                    .into_iter()
                    .map(|(decryptable_id, dec_share)| Task::CreateDecShare {
                        decryptable_id,
                        packed: None,
                        dec_share: Some(dec_share),
                    })
                    .collect(),
            },
        )
        .await
    }

    pub async fn create_user_actions(
        &self,
        user_id: UserId,
        action: Action,
    ) -> Result<CreateUserActionResponse> {
        self.post(
            format!("/users/{user_id}/actions"),
            &CreateUserActionRequest { action },
        )
        .await
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::{
        client::{Client, HttpClient},
        server::{app, ServerState},
        Result,
    };
    use axum::{body::Body, routing::RouterIntoService, Router};
    use core::{future::Future, ops::DerefMut};
    use hyper::{Request, Response};
    use std::sync::{Arc, Mutex};
    use tower::Service;

    #[derive(Clone)]
    pub(crate) struct MockHttpClient {
        router: Arc<Mutex<RouterIntoService<Body>>>,
    }

    impl MockHttpClient {
        fn new(router: Router) -> Self {
            MockHttpClient {
                router: Arc::new(Mutex::new(router.into_service())),
            }
        }
    }

    impl HttpClient for MockHttpClient {
        type Body = Body;

        fn request(
            &self,
            req: Request<Body>,
        ) -> impl Future<Output = Result<Response<Self::Body>>> {
            return inner(self.router.lock().unwrap(), req);

            async fn inner(
                mut router: impl DerefMut<Target = RouterIntoService<Body>>,
                req: Request<Body>,
            ) -> Result<Response<Body>> {
                Ok(router.call(req).await.unwrap())
            }
        }
    }

    impl Client<MockHttpClient> {
        pub(crate) fn mock(state: Arc<Mutex<ServerState>>) -> Self {
            Self {
                uri: "http://mock".to_string(),
                inner: MockHttpClient::new(app::router().with_state(state)),
            }
        }
    }
}
