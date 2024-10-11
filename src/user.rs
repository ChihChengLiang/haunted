use crate::{
    client::{Client, HttpClient},
    phantom::{
        HierarchicalSeedableRng, PhantomBsKeyShare, PhantomCrs, PhantomOps, PhantomPk,
        PhantomPkShare, PhantomRpKeyShare, PhantomSk, PhantomSkKs,
    },
    server::app::{Action, AppStatus, Decryptable, GetSetupResponse, Task, UserId},
    Result,
};
use anyhow::bail;
use axum::body::Body;
use core::time::Duration;
use hyper_util::client::legacy::{connect::HttpConnector, Client as HyperUtilClient};
use itertools::{chain, Itertools};
use rand::{rngs::StdRng, SeedableRng};
use std::sync::OnceLock;
use tokio::time::sleep;

pub struct User<H: HttpClient = HyperUtilClient<HttpConnector, Body>> {
    client: Client<H>,
    user_id: usize,
    seed: <StdRng as SeedableRng>::Seed,
    crs: PhantomCrs,
    ops: PhantomOps,
    pk: OnceLock<PhantomPk>,
}

impl User {
    pub async fn connect(
        server_uri: impl ToString,
        user_id: usize,
        seed: <StdRng as SeedableRng>::Seed,
    ) -> Result<Self> {
        Self::new(Client::new(server_uri), user_id, seed).await
    }
}

impl<H: HttpClient> User<H> {
    pub async fn new(
        client: Client<H>,
        user_id: usize,
        seed: <StdRng as SeedableRng>::Seed,
    ) -> Result<Self> {
        let GetSetupResponse { param, crs } = client.get_setup().await?;
        let ops = PhantomOps::new(param);
        Ok(Self {
            client,
            user_id,
            seed,
            crs,
            ops,
            pk: Default::default(),
        })
    }

    pub fn user_id(&self) -> UserId {
        self.user_id
    }

    fn deterministic_rng(&self, path: &[usize]) -> StdRng {
        StdRng::from_hierarchical_seed(self.seed, path)
    }

    fn sk(&self) -> PhantomSk {
        self.ops
            .sk_gen(StdRng::from_hierarchical_seed(self.seed, &[0, 0]))
    }

    fn sk_ks(&self) -> PhantomSkKs {
        self.ops
            .sk_ks_gen(StdRng::from_hierarchical_seed(self.seed, &[0, 1]))
    }

    fn pk_share_gen(&self) -> PhantomPkShare {
        self.ops
            .pk_share_gen(&self.crs, &self.sk(), self.deterministic_rng(&[1, 0]))
    }

    fn rp_key_share_gen(&self) -> PhantomRpKeyShare {
        self.ops
            .rp_key_share_gen(&self.crs, &self.sk(), self.deterministic_rng(&[1, 1]))
    }

    fn bs_key_share_gen(&self) -> PhantomBsKeyShare {
        self.ops.bs_key_share_gen(
            &self.crs,
            self.user_id,
            &self.sk(),
            self.pk.get().unwrap(),
            &self.sk_ks(),
            self.deterministic_rng(&[1, 2]),
        )
    }

    pub fn decrypt(&self, decryptable: &Decryptable) -> Vec<bool> {
        assert!(decryptable.dec_shares.len() >= self.ops.param().total_shares - 1);
        if decryptable.dec_shares.len() == self.ops.param().total_shares - 1 {
            let my_share = self.ops.decrypt_share(&self.sk(), &decryptable.packed);
            self.ops.aggregate_rp_dec_shares(
                &decryptable.packed,
                chain![&decryptable.dec_shares, [&my_share]],
            )
        } else {
            self.ops
                .aggregate_rp_dec_shares(&decryptable.packed, &decryptable.dec_shares)
        }
    }

    pub async fn get_tasks(&self) -> Result<Vec<Task>> {
        self.client
            .get_user_tasks(self.user_id)
            .await
            .map(|response| response.tasks)
    }

    pub async fn get_decryptables(&self) -> Result<Vec<Decryptable>> {
        self.client
            .get_user_decryptables(self.user_id)
            .await
            .map(|response| response.decryptables)
    }

    pub async fn demo(&self, ms: [bool; 10]) -> Result<()> {
        let Some(pk) = self.pk.get() else {
            bail!("pk is not got yet");
        };

        let ct_batched = self.ops.batched_pk_encrypt(pk, ms);
        self.client
            .create_user_actions(self.user_id, Action::Demo(ct_batched))
            .await?;

        Ok(())
    }

    pub async fn participate_key_gen(&self) -> Result<()> {
        loop {
            match self.client.get_status().await?.status {
                AppStatus::WaitingForPkShare(user_ids) => {
                    if user_ids.contains(&self.user_id) {
                        self.client
                            .create_user_pk_share(self.user_id, self.pk_share_gen())
                            .await?;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
                AppStatus::WaitingForRpKeyShare(user_ids) => {
                    if user_ids.contains(&self.user_id) {
                        self.client
                            .create_user_rp_key_share(self.user_id, self.rp_key_share_gen())
                            .await?;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
                AppStatus::WaitingForBsKeyShare(user_ids) => {
                    if self.pk.get().is_none() {
                        self.pk.set(self.client.get_pk().await?.pk).unwrap();
                    }
                    if user_ids.contains(&self.user_id) {
                        self.client
                            .create_user_bs_key_share(self.user_id, self.bs_key_share_gen())
                            .await?;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
                AppStatus::AggregatingKeyShare | AppStatus::InitializingGame => {
                    sleep(Duration::from_millis(100)).await
                }
                AppStatus::PlayingGame(_) => break,
            }
        }
        Ok(())
    }

    pub async fn wait_until_game_ready(&self) -> Result<()> {
        loop {
            let status = self.client.get_status().await.unwrap().status;
            match status {
                AppStatus::PlayingGame(_) => break Ok(()),
                _ => sleep(Duration::from_secs(1)).await,
            }
        }
    }

    pub async fn participate_decryption(&self) -> Result<()> {
        loop {
            let tasks = self.get_tasks().await?;
            if !tasks.is_empty() {
                let dec_shares = tasks
                    .into_iter()
                    .map(|task| match task {
                        Task::CreateDecShare {
                            decryptable_id,
                            packed,
                            ..
                        } => (
                            decryptable_id,
                            self.ops.decrypt_share(&self.sk(), &packed.unwrap()),
                        ),
                    })
                    .collect_vec();
                self.client
                    .create_decryption_share(self.user_id, dec_shares)
                    .await?;
            } else {
                sleep(Duration::from_millis(500)).await
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        client::Client,
        server::{
            test::{TEST_CRS, TEST_PARAM},
            ServerState,
        },
        test::ItertoolsExt,
        user::User,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::sync::Arc;

    #[tokio::test]
    async fn key_gen() {
        let state = ServerState::new(TEST_PARAM, TEST_CRS);
        assert!(state.lock().unwrap().app.worker_key().is_none());

        let client = Client::mock(Arc::clone(&state));
        let users = (0..TEST_PARAM.total_shares)
            .map(|user_id| User::new(client.clone(), user_id, StdRng::from_entropy().gen()))
            .try_join_vec()
            .await
            .unwrap();
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
    }
}
