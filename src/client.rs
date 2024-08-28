use crate::{
    server::PARAMETER,
    types::{
        DecryptionShare, DecryptionShareSubmission, Seed, ServerKeyShare, ServerState,
        SksSubmission, UserId,
    },
};
use anyhow::{anyhow, bail, Error};
use indicatif::{ProgressBar, ProgressStyle};
use phantom_zone::{
    gen_client_key, gen_server_key_share, set_common_reference_seed, set_parameter_set,
};
use reqwest::{self, header::CONTENT_TYPE, Client};
use rocket::serde::msgpack;
use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::AsyncRead;
use tokio_util::io::ReaderStream;

pub struct Wallet<RQ: Request> {
    pub(crate) rc: RQ,
}

impl Wallet<ProductionClient> {
    pub fn new(url: &str) -> Self {
        Self {
            rc: ProductionClient::new(url),
        }
    }
}

impl<RQ: Request> Wallet<RQ> {
    async fn get_seed(&self) -> Result<Seed, Error> {
        self.rc.get("/param").await
    }

    async fn register(&self) -> Result<UserId, Error> {
        self.rc.post_nobody("/register").await
    }

    async fn submit_sks(&self, user_id: UserId, sks: &ServerKeyShare) -> Result<UserId, Error> {
        let submission = SksSubmission {
            user_id,
            sks: sks.clone(),
        };
        self.rc.post_msgpack("/submit", &submission).await
    }
    /// Complete the flow to derive server key shares
    ///
    /// Wait actions from other users
    pub async fn run_setup(&self) -> Result<(), Error> {
        let seed = self.get_seed().await?;
        set_parameter_set(PARAMETER);
        set_common_reference_seed(seed);
        let client_key = gen_client_key();

        let user_id = self.register().await?;
        // Wait registration to conclude
        let total_users = 0;
        let sks = gen_server_key_share(user_id, total_users, &client_key);
        self.submit_sks(user_id, &sks).await?;

        Ok(())
    }

    /// Run this in background
    pub fn serve_decryption_keys(&self) {
        // Listen to published decryptables
        // Submit decryption share if requested
        // Decrypt decryptables whenever possible
    }
}

pub trait Request {
    fn get<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<T, Error>>;
    fn post_nobody<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<T, Error>>;

    fn post<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<T, Error>>;

    fn post_msgpack<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> impl Future<Output = Result<T, Error>>;
}

struct ProductionClient {
    url: String,
    client: reqwest::Client,
}

impl ProductionClient {
    fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: Client::new(),
        }
    }

    fn path(&self, path: &str) -> String {
        format!("{}/{}", self.url, path)
    }

    async fn handle_response<T: Send + for<'de> Deserialize<'de> + 'static>(
        response: reqwest::Response,
    ) -> Result<T, Error> {
        match response.status().as_u16() {
            200 => Ok(response.json::<T>().await?),
            _ => {
                let err = response.text().await?;
                bail!("Server responded error: {:?}", err)
            }
        }
    }
}

impl Request for ProductionClient {
    fn get<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<T, Error>> {
        async {
            let response = self.client.get(self.path(path)).send().await?;
            Self::handle_response(response).await
        }
    }

    fn post_nobody<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<T, Error>> {
        async {
            let response = self.client.post(self.path(path)).send().await?;
            Self::handle_response(response).await
        }
    }

    fn post<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<T, Error>> {
        async {
            let response = self.client.post(self.path(path)).body(body).send().await?;
            Self::handle_response(response).await
        }
    }

    fn post_msgpack<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> impl Future<Output = Result<T, Error>> {
        async {
            let body = msgpack::to_compact_vec(body)?;
            let reader = ProgressReader::new(&body, 128 * 1024);
            let stream = ReaderStream::new(reader);

            let response = self
                .client
                .post(self.path(path))
                .header(CONTENT_TYPE, "application/msgpack")
                .body(reqwest::Body::wrap_stream(stream))
                .send()
                .await?;
            Self::handle_response(response).await
        }
    }
}

struct ProgressReader {
    inner: Vec<u8>,
    progress_bar: ProgressBar,
    position: usize,
    chunk_size: usize,
}

impl ProgressReader {
    fn new(body: &[u8], chunk_size: usize) -> Self {
        let total_bytes = body.len() as u64;
        println!("Total size {} B", total_bytes);
        let bar = ProgressBar::new(total_bytes);
        bar.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {percent}% {bytes_per_sec} {msg}",
            )
            .unwrap()
            .progress_chars("##-"),
        );
        bar.set_message("Uploading...");

        Self {
            inner: body.to_vec(),
            progress_bar: bar,
            position: 0,
            chunk_size,
        }
    }
}

impl AsyncRead for ProgressReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        let remaining = self.inner.len() - self.position;
        let to_read = self.chunk_size.min(remaining.min(buf.remaining()));
        let end = self.position + to_read;
        buf.put_slice(&self.inner[self.position..end]);
        self.position = end;
        self.progress_bar.set_position(self.position as u64);

        if to_read == 0 {
            self.progress_bar.finish_with_message("Upload complete")
        }

        Poll::Ready(Ok(()))
    }
}
