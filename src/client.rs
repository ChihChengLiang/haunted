use crate::{
    phantom::Client as PhantomClient,
    server::*,
    types::{
        AnnotatedDecryptionShare, BskShareSubmission, Cipher, CipherSubmission,
        CreateTaskSubmission, Decryptable, DecryptionShareSubmission, ParamCRS, PkShareSubmission,
        ServerState, Task, TaskId, TaskInputSubmission, TaskStatus, UserId,
    },
};

use anyhow::{bail, Error};
use indicatif::{ProgressBar, ProgressStyle};
use phantom_zone_evaluator::boolean::fhew::prelude::{NonNativePowerOfTwo, PrimeRing};
use reqwest::{self, header::CONTENT_TYPE, Client};
use rocket::{serde::msgpack, uri};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::AsyncRead;
use tokio::time::sleep;
use tokio_util::io::ReaderStream;

pub struct Wallet {
    pub(crate) rc: ProductionClient,
}

impl Wallet {
    pub fn new(url: &str) -> Self {
        Self {
            rc: ProductionClient::new(url),
        }
    }
}

impl Wallet {
    async fn wait_for_server_state(
        &self,
        desired_state: ServerState,
    ) -> Result<ServerState, Error> {
        const MAX_ATTEMPTS: u32 = 30;
        const DELAY_MS: u64 = 1000;

        for _ in 0..MAX_ATTEMPTS {
            if let Ok(status) = self.rc.get_status().await {
                if status == desired_state {
                    return Ok(status);
                }
            }
            sleep(Duration::from_millis(DELAY_MS)).await;
        }
        bail!("Timed out waiting for server state: {:?}", desired_state)
    }

    async fn acquire_pk(&self, user_id: UserId, pk_share: Vec<u8>) -> Result<Vec<u8>, Error> {
        // Submit the public key share
        let _: UserId = self.rc.submit_pk_shares(user_id, pk_share).await?;
        for _ in 0..10 {
            if let Ok(server_pk) = self.rc.get_aggregated_pk().await {
                return Ok(server_pk);
            }
            sleep(Duration::from_millis(100)).await;
        }
        bail!("Failed to get aggregated public key".to_string());
    }

    /// Complete the flow to derive server key shares
    ///
    /// Wait actions from other users
    pub async fn run_setup(&self) -> Result<SetupWallet, Error> {
        let (param, crs) = self.rc.get_param_crs().await?;
        let user_id = self.rc.register().await?;
        let mut pc = PhantomClient::<PrimeRing, NonNativePowerOfTwo>::new(param, crs, user_id);
        self.wait_for_server_state(ServerState::ReadyForPkShares)
            .await?;
        let server_pk = self.acquire_pk(user_id, pc.pk_share_gen()).await?;
        pc.receive_pk(&server_pk);
        self.wait_for_server_state(ServerState::ReadyForBskShares)
            .await?;
        self.rc.submit_bsks(user_id, pc.bs_key_share_gen()).await?;

        Ok(SetupWallet {
            rc: self.rc.clone(),
            user_id,
            pc,
            tasks: Default::default(),
        })
    }
}

pub struct SetupWallet {
    rc: ProductionClient,
    user_id: UserId,
    pc: PhantomClient<PrimeRing, NonNativePowerOfTwo>,
    tasks: HashMap<TaskId, TaskStatus>,
}

impl SetupWallet {
    pub async fn create_task(
        &mut self,
        required_inputs: Vec<UserId>,
        input: Vec<bool>,
    ) -> Result<TaskId, Error> {
        // Encrypt input
        let cipher = self.pc.pk_encrypt_bit(input);

        // Create task on server
        let task_id = self
            .rc
            .create_task(self.user_id, required_inputs, cipher)
            .await?;

        // Store task locally
        self.tasks.insert(task_id, TaskStatus::WaitingForInput);

        Ok(task_id)
    }

    pub async fn monitor_tasks(&mut self) -> Result<(), Error> {
        loop {
            let tasks = self.rc.get_tasks_for_user(self.user_id).await?;
            for task in tasks {
                self.update_task_status(task);
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    pub async fn handle_input_requests(&mut self) -> Result<(), Error> {
        loop {
            let tasks = self.rc.get_tasks_for_user(self.user_id).await?;
            for task in tasks {
                if task.status == TaskStatus::WaitingForInput
                    && !task.inputs.contains_key(&self.user_id)
                {
                    let input = vec![true, true]; // Customize this
                    let cipher = self.pc.pk_encrypt_bit(input);
                    self.rc
                        .submit_task_input(task.id, self.user_id, cipher)
                        .await?;
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    pub async fn handle_decryptable_requests(&mut self) -> Result<(), Error> {
        loop {
            let decryptables = self.rc.get_decryptables_for_user(self.user_id).await?;
            for (task_id, decryptable) in decryptables {
                let share = self.pc.decrypt_share_bits(&decryptable.word);
                self.rc
                    .submit_decryption_share(task_id, decryptable.id, self.user_id, share)
                    .await?;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    fn update_task_status(&mut self, task: Task) {
        self.tasks.insert(task.id, task.status.clone());
        if task.status == TaskStatus::Done {
            self.process_completed_task(task);
        }
    }

    fn process_completed_task(&self, task: Task) {
        // Implement logic to retrieve and decrypt the final result
    }

    // Implement other helper methods...
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
        println!("{}", path);
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

    async fn get<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
    ) -> Result<T, Error> {
        let response = self.client.get(self.path(path)).send().await?;
        Self::handle_response(response).await
    }

    async fn post_nobody<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
    ) -> Result<T, Error> {
        let response = self.client.post(self.path(path)).send().await?;
        Self::handle_response(response).await
    }

    async fn post<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<T, Error> {
        let response = self.client.post(self.path(path)).body(body).send().await?;
        Self::handle_response(response).await
    }
    async fn post_msgpack<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, Error> {
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

    pub async fn get_param_crs(&self) -> Result<ParamCRS, Error> {
        self.get(&uri!(get_param).to_string()).await
    }

    pub async fn register(&self) -> Result<UserId, Error> {
        self.post_nobody(&uri!(register).to_string()).await
    }

    pub async fn get_status(&self) -> Result<ServerState, Error> {
        self.get(&uri!(get_status).to_string()).await
    }

    pub async fn submit_pk_shares(
        &self,
        user_id: UserId,
        pk_share: Vec<u8>,
    ) -> Result<UserId, Error> {
        self.post_msgpack(
            &uri!(submit_pk_shares).to_string(),
            &PkShareSubmission { user_id, pk_share },
        )
        .await
    }

    pub async fn get_aggregated_pk(&self) -> Result<Vec<u8>, Error> {
        self.get(&uri!(get_aggregated_pk).to_string()).await
    }

    pub async fn submit_bsks(&self, user_id: UserId, bsk_share: Vec<u8>) -> Result<UserId, Error> {
        self.post_msgpack(
            &uri!(submit_bsks).to_string(),
            &BskShareSubmission { user_id, bsk_share },
        )
        .await
    }

    pub async fn create_task(
        &self,
        initiator: UserId,
        required_inputs: Vec<UserId>,
        initiator_input: Cipher,
    ) -> Result<TaskId, Error> {
        self.post_msgpack(
            &uri!(create_task).to_string(),
            &CreateTaskSubmission {
                initiator,
                required_inputs,
                initiator_input,
            },
        )
        .await
    }

    pub async fn get_tasks_for_user(&self, user_id: UserId) -> Result<Vec<Task>, Error> {
        self.get(&uri!(get_tasks_for_user(user_id)).to_string())
            .await
    }

    pub async fn submit_task_input(
        &self,
        task_id: TaskId,
        user_id: UserId,
        input: Cipher,
    ) -> Result<(), Error> {
        self.post_msgpack(
            &uri!(submit_task_input).to_string(),
            &TaskInputSubmission {
                task_id,
                user_id,
                input,
            },
        )
        .await
    }

    pub async fn get_decryptables_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<(TaskId, Decryptable)>, Error> {
        self.get(&uri!(get_decryptables_for_user(user_id)).to_string())
            .await
    }

    pub async fn submit_decryption_share(
        &self,
        task_id: TaskId,
        decryptable_id: usize,
        user_id: UserId,
        share: Vec<u8>,
    ) -> Result<(), Error> {
        self.post_msgpack(
            &uri!(submit_decryption_share).to_string(),
            &DecryptionShareSubmission {
                task_id,
                decryptable_id,
                user_id,
                share,
            },
        )
        .await
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
