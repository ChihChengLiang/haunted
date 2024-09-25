use crate::{
    phantom::Client as PhantomClient,
    server::*,
    types::{AnnotatedDecryptionShare, Decryptable, DecryptionShareSubmission, ParamCRS, UserId},
};
use anyhow::{bail, Error};
use indicatif::{ProgressBar, ProgressStyle};
use phantom_zone_evaluator::boolean::fhew::prelude::{NonNativePowerOfTwo, PrimeRing};
use reqwest::{self, header::CONTENT_TYPE, Client};
use rocket::{serde::msgpack, uri};
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

impl<RQ: Request + Clone> Wallet<RQ> {
    async fn get_param_crs(&self) -> Result<ParamCRS, Error> {
        self.rc.get(&uri!(get_param).to_string()).await
    }

    async fn register(&self) -> Result<UserId, Error> {
        self.rc.post_nobody("/register").await
    }

    async fn acquire_pk(
        &self,
        pc: &mut PhantomClient<PrimeRing, NonNativePowerOfTwo>,
    ) -> Result<Vec<u8>, Error> {
        let pk_share = pc.pk_share_gen();
        let server_pk = vec![];
        pc.receive_pk(&server_pk);
        Ok(vec![])
    }

    async fn submit_bs_key_share(&self, bs_key_share: Vec<u8>) -> Result<UserId, Error> {
        self.rc
            .post_msgpack(&uri!(submit_bsks).to_string(), &bs_key_share)
            .await
    }

    /// Complete the flow to derive server key shares
    ///
    /// Wait actions from other users
    pub async fn run_setup(&self) -> Result<SetupWallet<RQ>, Error> {
        let (param, crs) = self.get_param_crs().await?;
        let user_id = self.register().await?;
        let mut pc = PhantomClient::<PrimeRing, NonNativePowerOfTwo>::new(param, crs, user_id);
        self.acquire_pk(&mut pc).await?;
        self.submit_bs_key_share(pc.bs_key_share_gen()).await?;

        Ok(SetupWallet {
            rc: self.rc.clone(),
            user_id,
            pc,
        })
    }
}

pub struct SetupWallet<RQ: Request> {
    rc: RQ,
    user_id: UserId,
    pc: PhantomClient<PrimeRing, NonNativePowerOfTwo>,
}

impl<RQ: Request> SetupWallet<RQ> {
    async fn listen_for_decryptables(&self) -> Result<Vec<Decryptable>, Error> {
        // Poll the server for new decryptables
        let decryptables: Vec<Decryptable> = self.rc.get("/decryptables").await?;
        Ok(decryptables)
    }

    fn generate_decryption_share(&self, decryptable: &Decryptable) -> AnnotatedDecryptionShare {
        // Generate decryption share for the given decryptable
        let decryption_share = self.pc.decrypt_share_u8(&decryptable.word);

        // Create an AnnotatedDecryptionShare with the decryptable's ID and the generated share
        (decryptable.id, decryption_share)
    }

    async fn submit_decryption_share(&self, share: AnnotatedDecryptionShare) -> Result<(), Error> {
        let submission = DecryptionShareSubmission {
            user_id: self.user_id,
            decryption_shares: vec![share],
        };
        self.rc
            .post_msgpack("/submit_decryption_share", &submission)
            .await?;
        Ok(())
    }

    async fn handle_decrypted_data(&self) {
        todo!()
    }

    pub async fn serve_decryption_keys(&self) -> Result<(), Error> {
        loop {
            // Listen to published decryptables
            let decryptables = self.listen_for_decryptables().await?;

            for decryptable in decryptables {
                // Submit decryption share if requested
                if decryptable.should_contribute(self.user_id) {
                    let share = self.generate_decryption_share(&decryptable);
                    self.submit_decryption_share(share).await?;
                }

                // Decrypt decryptables whenever possible
                if decryptable.is_complete {
                    // let plaintext = self.decrypt_decryptable(&decryptable)?;
                    // self.handle_decrypted_data(plaintext).await?;
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
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

#[derive(Debug, Clone)]
pub struct ProductionClient {
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
