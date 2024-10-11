use crate::{
    circuit::CircuitId,
    phantom::{
        PhantomBatchedCt, PhantomBsKey, PhantomBsKeyShare, PhantomCrs, PhantomCt, PhantomOps,
        PhantomPackedCt, PhantomPackedCtDecShare, PhantomParam, PhantomPk, PhantomPkShare,
        PhantomRpKey, PhantomRpKeyPrep, PhantomRpKeyShare,
    },
    server::{
        scheduler::{TaskId, TaskRequest, TaskResponse},
        util::{bad_request, internal_server_error, Bincode},
        ServerState,
    },
    worker::WorkerKey,
    Result,
};
use anyhow::{anyhow, bail};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
    Router,
};
use core::{cell::OnceCell, mem::take};
use itertools::{chain, izip, Itertools};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub const BS_KEY_SIZE: usize = 32 << 20;

pub type UserId = usize;

#[derive(Clone, Debug, Default)]
struct UserState {
    pk_share: OnceCell<PhantomPkShare>,
    rp_key_share: OnceCell<PhantomRpKeyShare>,
    bs_key_share: OnceCell<PhantomBsKeyShare>,
}

impl UserState {
    fn try_set_pk_share(&self, pk_share: PhantomPkShare) -> Result<(), String> {
        self.pk_share
            .set(pk_share)
            .map_err(|_| "pk_share already set".to_string())
    }

    fn try_set_rp_key_share(&self, rp_key_share: PhantomRpKeyShare) -> Result<(), String> {
        self.rp_key_share
            .set(rp_key_share)
            .map_err(|_| "rp_key_share already set".to_string())
    }

    fn try_set_bs_key_share(&self, bs_key_share: PhantomBsKeyShare) -> Result<(), String> {
        self.bs_key_share
            .set(bs_key_share)
            .map_err(|_| "bs_key_share already set".to_string())
    }
}

#[derive(Debug)]
struct DecryptableState {
    ct_ids: Vec<CtId>,
    packed: PhantomPackedCt,
    dec_shares: Vec<Option<PhantomPackedCtDecShare>>,
    designated: Option<UserId>,
}

impl DecryptableState {
    fn new(
        ct_ids: Vec<CtId>,
        packed: PhantomPackedCt,
        num_users: usize,
        designated: Option<UserId>,
    ) -> Self {
        Self {
            ct_ids,
            packed,
            dec_shares: vec![None; num_users],
            designated,
        }
    }

    fn is_waiting(&self, user_id: UserId) -> bool {
        match self.designated {
            Some(designated) if designated == user_id => false,
            _ => self.dec_shares[user_id].is_none(),
        }
    }

    fn is_decryptable(&self, user_id: UserId) -> bool {
        match self.designated {
            Some(designated) if designated == user_id => self
                .dec_shares
                .iter()
                .enumerate()
                .all(|(idx, dec_share)| idx == designated || dec_share.is_some()),
            Some(_) => false,
            None => self.dec_shares.iter().all(Option::is_some),
        }
    }

    fn insert_dec_share(
        &mut self,
        user_id: UserId,
        dec_share: PhantomPackedCtDecShare,
    ) -> Result<()> {
        if matches!(self.designated, Some(designated) if designated == user_id) {
            bail!("unexpected dec share from {user_id} of designated ct")
        }
        if self.dec_shares[user_id].replace(dec_share).is_some() {
            bail!("duplicated dec share from {user_id}")
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CtId {
    Demo(usize),
}

#[derive(Debug)]
struct GameState {
    round: usize,
    state: HashMap<CtId, PhantomCt>,
    staged: HashMap<CtId, PhantomCt>,
}

impl GameState {
    fn new(num_users: usize, ops: &PhantomOps, pk: &PhantomPk) -> Self {
        let mut rng = StdRng::from_entropy();
        let state = izip!(
            chain![(0..10 * (num_users + 1)).map(CtId::Demo)],
            ops.batched_pk_encrypt(pk, (0..10 * (num_users + 1)).map(|_| rng.gen()))
                .extract_all(ops.ring())
        )
        .collect();
        Self {
            round: 0,
            state,
            staged: HashMap::new(),
        }
    }

    fn try_commit(&mut self) -> Result<(), ()> {
        let ready = self.staged.len() == self.state.len() - 10;
        if !ready {
            return Err(());
        }

        for (key, value) in take(&mut self.staged) {
            self.state.insert(key, value);
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AppStatus {
    WaitingForPkShare(Vec<usize>),
    WaitingForRpKeyShare(Vec<usize>),
    WaitingForBsKeyShare(Vec<usize>),
    AggregatingKeyShare,
    InitializingGame,
    PlayingGame(usize),
}

#[derive(Debug)]
pub struct AppState {
    ops: PhantomOps,
    crs: PhantomCrs,
    users: Vec<UserState>,
    pk: OnceCell<PhantomPk>,
    rp_key: OnceCell<PhantomRpKey>,
    rp_key_prep: OnceCell<PhantomRpKeyPrep>,
    bs_key: OnceCell<PhantomBsKey>,
    game: OnceCell<GameState>,
    decryptable: Vec<DecryptableState>,
    scheduled: HashMap<TaskId, Vec<CtId>>,
}

impl AppState {
    pub(super) fn new(param: PhantomParam, crs: PhantomCrs) -> Self {
        Self {
            ops: PhantomOps::new(param),
            crs,
            users: vec![UserState::default(); param.total_shares],
            pk: Default::default(),
            rp_key: Default::default(),
            rp_key_prep: Default::default(),
            bs_key: Default::default(),
            game: Default::default(),
            decryptable: Default::default(),
            scheduled: Default::default(),
        }
    }

    fn status(&self) -> AppStatus {
        let pred = |user: &UserState| user.pk_share.get().is_none();
        if self.users.iter().any(pred) {
            return AppStatus::WaitingForPkShare(self.users.iter().positions(pred).collect());
        }
        let pred = |user: &UserState| user.rp_key_share.get().is_none();
        if self.users.iter().any(pred) {
            return AppStatus::WaitingForRpKeyShare(self.users.iter().positions(pred).collect());
        }
        let pred = |user: &UserState| user.bs_key_share.get().is_none();
        if self.users.iter().any(pred) {
            return AppStatus::WaitingForBsKeyShare(self.users.iter().positions(pred).collect());
        }
        if self.bs_key.get().is_none() {
            return AppStatus::AggregatingKeyShare;
        }
        match self.game.get() {
            Some(game) => AppStatus::PlayingGame(game.round),
            None => AppStatus::InitializingGame,
        }
    }

    fn parse_user_id(&self, user_id: String) -> Result<UserId, String> {
        match user_id.parse::<UserId>() {
            Ok(user_id) if user_id < self.users.len() => Ok(user_id),
            _ => Err(format!("invalid user id {user_id}")),
        }
    }

    fn aggregate_pk_shares(&self) {
        let pk = self.ops.aggregate_pk_shares(
            &self.crs,
            self.users.iter().map(|user| user.pk_share.get().unwrap()),
        );
        self.pk.set(pk).unwrap();
    }

    fn aggregate_rp_key_shares(&self) {
        let rp_key = self.ops.aggregate_rp_key_shares(
            &self.crs,
            self.users
                .iter()
                .map(|user| user.rp_key_share.get().unwrap()),
        );
        let rp_key_prep = self.ops.prepare_rp_key(&rp_key);
        self.rp_key.set(rp_key).unwrap();
        self.rp_key_prep.set(rp_key_prep).unwrap();
    }

    fn aggregate_bs_key_shares(&self) {
        let bs_key = self.ops.aggregate_bs_key_shares(
            &self.crs,
            self.users
                .iter()
                .map(|user| user.bs_key_share.get().unwrap()),
        );
        self.bs_key.set(bs_key).unwrap();
    }

    pub fn worker_key(&self) -> Option<WorkerKey> {
        Some(WorkerKey {
            param: *self.ops.param(),
            bs_key: self.bs_key.get().cloned()?,
            rp_key: self.rp_key.get().cloned()?,
        })
    }

    pub fn handle_task(&mut self, response: TaskResponse) {
        let game = self.game.get_mut().unwrap();
        let output_ct_ids = self.scheduled.remove(&response.task_id).unwrap();
        izip!(output_ct_ids, response.outputs).for_each(|(ct_id, ct)| {
            game.staged.insert(ct_id, ct);
        });
        if game.try_commit().is_ok() {
            self.make_decryptable();
        }
    }

    fn initialize_game(&mut self) {
        self.game
            .set(GameState::new(
                self.users.len(),
                &self.ops,
                self.pk.get().unwrap(),
            ))
            .unwrap();
        self.make_decryptable();
    }

    fn make_decryptable(&mut self) {
        self.decryptable = chain![
            [self.pack((0..10).map(CtId::Demo), None)],
            (0..self.users.len()).map(|user_id| {
                self.pack(
                    (10 * (user_id + 1)..).take(10).map(CtId::Demo),
                    Some(user_id),
                )
            })
        ]
        .collect();
    }

    fn pack(
        &self,
        ct_ids: impl IntoIterator<Item = CtId>,
        designated: Option<UserId>,
    ) -> DecryptableState {
        let ct_ids = ct_ids.into_iter().collect_vec();
        let packed = self.ops.pack(
            self.rp_key_prep.get().unwrap(),
            ct_ids
                .iter()
                .map(|ct_id| &self.game.get().unwrap().state[ct_id]),
        );
        DecryptableState::new(ct_ids, packed, self.users.len(), designated)
    }

    fn insert_dec_share(
        &mut self,
        decryptable_id: usize,
        user_id: UserId,
        dec_share: PhantomPackedCtDecShare,
    ) -> Result<()> {
        self.decryptable
            .get_mut(decryptable_id)
            .ok_or(anyhow!("invalid decryptable id {decryptable_id}"))?
            .insert_dec_share(user_id, dec_share)
    }
}

pub fn router() -> Router<Arc<Mutex<ServerState>>> {
    Router::new()
        .route("/status", get(get_status))
        .route("/setup", get(get_setup))
        .route("/pk", get(get_pk))
        .nest(
            "/users/:user_id",
            Router::new()
                .route("/pk_share", post(create_user_pk_share))
                .route("/rp_key_share", post(create_user_rp_key_share))
                .route("/bs_key_share", post(create_user_bs_key_share))
                .route("/tasks", get(get_user_tasks).put(update_user_tasks))
                .route("/decryptables", get(get_user_decryptables))
                .route("/actions", post(create_user_action))
                .layer(DefaultBodyLimit::max(BS_KEY_SIZE)),
        )
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetStatusResponse {
    pub status: AppStatus,
}

async fn get_status(
    State(state): State<Arc<Mutex<ServerState>>>,
) -> Result<Bincode<GetStatusResponse>, (StatusCode, String)> {
    let ServerState { app, .. } = &*state.lock().unwrap();
    Ok(Bincode(GetStatusResponse {
        status: app.status(),
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSetupResponse {
    pub param: PhantomParam,
    pub crs: PhantomCrs,
}

async fn get_setup(
    State(state): State<Arc<Mutex<ServerState>>>,
) -> Result<Bincode<GetSetupResponse>, (StatusCode, String)> {
    let ServerState { app, .. } = &*state.lock().unwrap();
    Ok(Bincode(GetSetupResponse {
        param: *app.ops.param(),
        crs: app.crs,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetPkResponse {
    pub pk: PhantomPk,
}

async fn get_pk(
    State(state): State<Arc<Mutex<ServerState>>>,
) -> Result<Bincode<GetPkResponse>, (StatusCode, String)> {
    let ServerState { app, .. } = &*state.lock().unwrap();
    match app.pk.get() {
        Some(pk) => Ok(Bincode(GetPkResponse { pk: pk.clone() })),
        None => Err(bad_request("pk is not ready yet")),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserPkShareRequest {
    pub pk_share: PhantomPkShare,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserPkShareResponse {}

async fn create_user_pk_share(
    Path(user_id): Path<String>,
    State(state): State<Arc<Mutex<ServerState>>>,
    Bincode(CreateUserPkShareRequest { pk_share }): Bincode<CreateUserPkShareRequest>,
) -> Result<Bincode<CreateUserPkShareResponse>, (StatusCode, String)> {
    let all_set = {
        let ServerState { app, .. } = &*state.lock().unwrap();

        let user_id = app.parse_user_id(user_id).map_err(bad_request)?;
        app.users[user_id]
            .try_set_pk_share(pk_share)
            .map_err(bad_request)?;

        app.users.iter().all(|user| user.pk_share.get().is_some())
    };

    if all_set {
        tokio::task::spawn_blocking(move || {
            let state = state.lock().unwrap();
            state.app.aggregate_pk_shares();
        });
    }

    Ok(Bincode(CreateUserPkShareResponse {}))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRpKeyShareRequest {
    pub rp_key_share: PhantomRpKeyShare,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRpKeyShareResponse {}

async fn create_user_rp_key_share(
    Path(user_id): Path<String>,
    State(state): State<Arc<Mutex<ServerState>>>,
    Bincode(CreateUserRpKeyShareRequest { rp_key_share }): Bincode<CreateUserRpKeyShareRequest>,
) -> Result<Bincode<CreateUserRpKeyShareResponse>, (StatusCode, String)> {
    let all_set = {
        let ServerState { app, .. } = &*state.lock().unwrap();

        let user_id = app.parse_user_id(user_id).map_err(bad_request)?;
        app.users[user_id]
            .try_set_rp_key_share(rp_key_share)
            .map_err(bad_request)?;

        app.users
            .iter()
            .all(|user| user.rp_key_share.get().is_some())
    };

    if all_set {
        tokio::task::spawn_blocking(move || state.lock().unwrap().app.aggregate_rp_key_shares());
    }

    Ok(Bincode(CreateUserRpKeyShareResponse {}))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserBsKeyShareRequest {
    pub bs_key_share: PhantomBsKeyShare,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserBsKeyShareResponse {}

async fn create_user_bs_key_share(
    Path(user_id): Path<String>,
    State(state): State<Arc<Mutex<ServerState>>>,
    Bincode(CreateUserBsKeyShareRequest { bs_key_share }): Bincode<CreateUserBsKeyShareRequest>,
) -> Result<Bincode<CreateUserBsKeyShareResponse>, (StatusCode, String)> {
    let all_set = {
        let ServerState { app, .. } = &*state.lock().unwrap();

        let user_id = app.parse_user_id(user_id).map_err(bad_request)?;
        app.users[user_id]
            .try_set_bs_key_share(bs_key_share)
            .map_err(bad_request)?;

        app.users
            .iter()
            .all(|user| user.bs_key_share.get().is_some())
    };
    if all_set {
        tokio::task::spawn_blocking(move || {
            let mut state = state.lock().unwrap();
            state.app.aggregate_bs_key_shares();
            let worker_key = state.app.worker_key().unwrap();
            state.scheduler.set_key(worker_key);
            state.app.initialize_game();
        });
    }

    Ok(Bincode(CreateUserBsKeyShareResponse {}))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Decryptable {
    pub ct_ids: Vec<CtId>,
    pub packed: PhantomPackedCt,
    pub dec_shares: Vec<PhantomPackedCtDecShare>,
}

impl From<&DecryptableState> for Decryptable {
    fn from(value: &DecryptableState) -> Self {
        Self {
            ct_ids: value.ct_ids.clone(),
            packed: value.packed.clone(),
            dec_shares: value.dec_shares.iter().flatten().cloned().collect(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetUserDecryptablesResponse {
    pub round: usize,
    pub decryptables: Vec<Decryptable>,
}

async fn get_user_decryptables(
    Path(user_id): Path<String>,
    State(state): State<Arc<Mutex<ServerState>>>,
) -> Result<Bincode<GetUserDecryptablesResponse>, (StatusCode, String)> {
    let ServerState { app, .. } = &*state.lock().unwrap();

    let user_id = app.parse_user_id(user_id).map_err(bad_request)?;
    let Some(game) = app.game.get() else {
        return Err(bad_request("game has started yet"));
    };

    let decryptables = app
        .decryptable
        .iter()
        .filter(|decryptable| decryptable.is_decryptable(user_id))
        .map(Decryptable::from)
        .collect();

    Ok(Bincode(GetUserDecryptablesResponse {
        round: game.round,
        decryptables,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Task {
    CreateDecShare {
        decryptable_id: usize,
        packed: Option<PhantomPackedCt>,
        dec_share: Option<PhantomPackedCtDecShare>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetUserTasksResponse {
    pub tasks: Vec<Task>,
}

async fn get_user_tasks(
    Path(user_id): Path<String>,
    State(state): State<Arc<Mutex<ServerState>>>,
) -> Result<Bincode<GetUserTasksResponse>, (StatusCode, String)> {
    let ServerState { app, .. } = &*state.lock().unwrap();

    let user_id = app.parse_user_id(user_id).map_err(bad_request)?;
    if app.game.get().is_none() {
        return Err(bad_request("game has started yet"));
    };

    let tasks = app
        .decryptable
        .iter()
        .enumerate()
        .filter(|(_, decryptable)| decryptable.is_waiting(user_id))
        .map(|(decryptable_id, decryptable)| Task::CreateDecShare {
            decryptable_id,
            packed: Some(decryptable.packed.clone()),
            dec_share: None,
        })
        .collect();

    Ok(Bincode(GetUserTasksResponse { tasks }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateUserTasksRequest {
    pub tasks: Vec<Task>,
}

async fn update_user_tasks(
    Path(user_id): Path<String>,
    State(state): State<Arc<Mutex<ServerState>>>,
    Bincode(UpdateUserTasksRequest { tasks }): Bincode<UpdateUserTasksRequest>,
) -> Result<Bincode<()>, (StatusCode, String)> {
    let ServerState { app, .. } = &mut *state.lock().unwrap();

    let user_id = app.parse_user_id(user_id).map_err(bad_request)?;
    if app.game.get().is_none() {
        return Err(bad_request("game has started yet"));
    };

    for task in tasks {
        match task {
            Task::CreateDecShare {
                decryptable_id,
                dec_share,
                ..
            } => app
                .insert_dec_share(
                    decryptable_id,
                    user_id,
                    dec_share.ok_or("missing dec_share").map_err(bad_request)?,
                )
                .map_err(bad_request)?,
        }
    }

    Ok(Bincode(()))
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Action {
    // Demo action to trigger Demo circuit with inputs.
    Demo(PhantomBatchedCt),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserActionRequest {
    pub action: Action,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserActionResponse {}

async fn create_user_action(
    Path(user_id): Path<String>,
    State(state): State<Arc<Mutex<ServerState>>>,
    Bincode(CreateUserActionRequest { action }): Bincode<CreateUserActionRequest>,
) -> Result<Bincode<CreateUserActionResponse>, (StatusCode, String)> {
    let ServerState { app, scheduler } = &mut *state.lock().unwrap();

    let user_id = app.parse_user_id(user_id).map_err(bad_request)?;
    let Some(game) = app.game.get() else {
        return Err(bad_request("game has started yet"));
    };

    match action {
        Action::Demo(ct_batched) => {
            let task_id = TaskId::new_v4();
            // Input CtId of the demo circuit.
            let input_ct_ids = (10 * (user_id + 1)..)
                .take(10)
                .map(CtId::Demo)
                .collect_vec();
            // Output CtId to be updated, same as input for the demo circuit.
            let output_ct_ids = input_ct_ids.clone();
            // Remember the output_ct_ids to update later.
            app.scheduled.insert(task_id, output_ct_ids);
            scheduler
                .schedule_task_request(TaskRequest {
                    task_id,
                    circuit_id: CircuitId::Demo,
                    inputs: chain![
                        input_ct_ids.iter().map(|idx| game.state[idx].clone()),
                        ct_batched.extract_all(app.ops.ring())
                    ]
                    .collect(),
                })
                .map_err(internal_server_error)?
        }
    };

    Ok(Bincode(CreateUserActionResponse {}))
}
