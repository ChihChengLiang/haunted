use crate::phantom::Server as PhantomServer;
use phantom_zone_evaluator::boolean::fhew::prelude::*;
use rand::rngs::StdRng;
use rocket::serde::{Deserialize, Serialize};
use rocket::tokio::sync::Mutex;
use rocket::Responder;
use std::collections::{HashMap, VecDeque};
use std::fmt::Display;
use std::fmt::{self, Debug};
use std::sync::Arc;
use thiserror::Error;

pub type UserId = usize;
/// Decryption share for a word from one user.
pub type DecryptionShare = Vec<u8>;
pub type Word = Vec<u8>;
pub type ServerKeyShare = Vec<u8>;
pub type ParamCRS = (FhewBoolMpiParam, FhewBoolMpiCrs<StdRng>);
pub type Cipher = Vec<u8>;

pub type TaskId = usize;

/// Represents the current state of a task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskStatus {
    /// Task is waiting for input from required users
    WaitingForInput,
    /// All inputs received, task is ready to be processed
    ReadyToRun,
    /// Task is currently being processed
    Running,
    /// Computation complete, waiting for decryption shares
    WaitingDecryptionShares,
    /// Task is fully complete and results are available
    Done,
}

/// Represents a FHE computation task for the server to perform
///
/// A task is created by an initiator. It goes through these stages:
/// - Waiting for the inputs from other users
/// - Waiting for the server to run the actual computation
/// - Waiting for users to contribute decryption shares to the computation outputs
/// - The users can decrypt the comutation outputs from the completed task.
#[derive(Serialize, Deserialize, Clone)]
pub struct Task {
    pub id: TaskId,
    pub initiator: UserId,
    /// List of user IDs required to provide input for this task
    pub required_inputs: Vec<UserId>,
    pub status: TaskStatus,
    /// Collected inputs from users, keyed by user ID
    pub inputs: HashMap<UserId, Cipher>,
    /// Decryptables generated as a result of the task computation
    pub decryptables: Vec<Decryptable>,
}

impl Task {
    pub fn new(
        id: TaskId,
        initiator: UserId,
        required_inputs: Vec<UserId>,
        initiator_input: Cipher,
    ) -> Self {
        let mut inputs = HashMap::new();
        inputs.insert(initiator, initiator_input);
        Self {
            id,
            initiator,
            required_inputs,
            status: TaskStatus::WaitingForInput,
            inputs,
            decryptables: Vec::new(),
        }
    }

    pub fn is_ready_to_run(&self) -> bool {
        self.required_inputs
            .iter()
            .all(|user_id| self.inputs.contains_key(user_id))
    }

    pub fn add_input(&mut self, user_id: UserId, input: Cipher) -> Result<(), Error> {
        if !self.required_inputs.contains(&user_id) {
            return Err(Error::UnexpectedInput { user_id });
        }
        self.inputs.insert(user_id, input);
        Ok(())
    }

    pub fn get_decryptables_for_user(&self, user_id: UserId) -> Vec<&Decryptable> {
        self.decryptables
            .iter()
            .filter(|d| d.should_contribute(user_id) && !d.shares.contains_key(&user_id))
            .collect()
    }
}

impl fmt::Debug for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Task")
            .field("id", &self.id)
            .field("initiator", &self.initiator)
            .field("required_inputs", &self.required_inputs)
            .field("status", &self.status)
            .field("inputs", &format!("{} inputs", self.inputs.len()))
            .field(
                "decryptables",
                &format!("{} decryptables", self.decryptables.len()),
            )
            .finish()
    }
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("Wrong server state: expect {expect} but got {got}")]
    WrongServerState { expect: String, got: String },
    #[error("User #{user_id} is unregistered")]
    UnregisteredUser { user_id: usize },
    #[error("The public key share from user #{user_id} not found")]
    PkShareNotFound { user_id: UserId },
    #[error("The bootstrap key share from user #{user_id} not found")]
    BskShareNotFound { user_id: UserId },
    #[error("Task #{task_id} not found")]
    TaskNotFound { task_id: TaskId },
    #[error("Unexpected input from user #{user_id}")]
    UnexpectedInput { user_id: UserId },
    #[error("Wrong task state for task #{task_id}: expected {expected:?}, got {got:?}")]
    WrongTaskState {
        task_id: TaskId,
        expected: TaskStatus,
        got: TaskStatus,
    },
    #[error("Decryptable #{decryptable_id} not found in task #{task_id}")]
    DecryptableNotFound {
        task_id: TaskId,
        decryptable_id: usize,
    },
    #[error("Unexpected decryption share from user #{user_id}")]
    UnexpectedDecryptionShare { user_id: UserId },
}

#[derive(Responder)]
pub(crate) enum ErrorResponse {
    #[response(status = 500, content_type = "json")]
    ServerError(String),
    #[response(status = 404, content_type = "json")]
    NotFoundError(String),
}

impl From<Error> for ErrorResponse {
    fn from(error: Error) -> Self {
        match error {
            Error::WrongServerState { .. } => ErrorResponse::ServerError(error.to_string()),
            Error::PkShareNotFound { .. }
            | Error::BskShareNotFound { .. }
            | Error::UnregisteredUser { .. } => ErrorResponse::NotFoundError(error.to_string()),
            _ => ErrorResponse::ServerError(error.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServerState {
    /// Users are allowed to join the computation
    ReadyForJoining,
    /// Ready for public key shares
    ReadyForPkShares,
    /// Ready for bootstrap key shares
    ReadyForBskShares,
    /// We can now accept ciphertexts
    ReadyForInputs,
}

impl ServerState {
    fn ensure(&self, expect: Self) -> Result<&Self, Error> {
        if *self == expect {
            Ok(self)
        } else {
            Err(Error::WrongServerState {
                expect: expect.to_string(),
                got: self.to_string(),
            })
        }
    }
    fn transit(&mut self, next: Self) {
        *self = next;
    }
}

impl Display for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[[ {:?} ]]", self)
    }
}

pub(crate) type MutexServerStorage = Arc<Mutex<ServerStorage>>;

pub(crate) struct ServerStorage {
    /// Close registration when this number is reached
    pub(crate) n_users: usize,
    pub(crate) ps: PhantomServer<NoisyPrimeRing, NonNativePowerOfTwo>,
    pub(crate) state: ServerState,
    pub(crate) users: Vec<UserRecord>,
    pub(crate) task_queue: VecDeque<Task>,
    pub(crate) next_task_id: TaskId,
}

impl fmt::Debug for ServerStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerStorage")
            .field("state", &self.state)
            .field("users", &self.users)
            .finish()
    }
}

impl ServerStorage {
    pub(crate) fn new(param: FhewBoolMpiParam, n_users: usize) -> Self {
        Self {
            n_users,
            ps: PhantomServer::new(param),
            state: ServerState::ReadyForJoining,
            users: vec![],
            task_queue: VecDeque::new(),
            next_task_id: 0,
        }
    }

    pub(crate) fn get_param_crs(&self) -> ParamCRS {
        self.ps.get_param_crs()
    }

    pub(crate) fn is_users_full(&self) -> bool {
        self.n_users == self.users.len()
    }

    pub(crate) fn add_user(&mut self) -> UserId {
        let id = self.users.len();
        self.users.push(UserRecord {
            id,
            storage: UserStorage::Empty,
        });
        id
    }

    pub(crate) fn ensure(&self, state: ServerState) -> Result<(), Error> {
        self.state.ensure(state)?;
        Ok(())
    }

    pub(crate) fn transit(&mut self, state: ServerState) {
        self.state.transit(state.clone());
        println!("Sever state {}", state);
    }

    pub(crate) fn get_user(&mut self, user_id: UserId) -> Result<&mut UserRecord, Error> {
        self.users
            .get_mut(user_id)
            .ok_or(Error::UnregisteredUser { user_id })
    }

    pub(crate) fn check_pk_share_submission(&self) -> bool {
        self.users
            .iter()
            .all(|user| matches!(user.storage, UserStorage::PkShare(..)))
    }

    pub(crate) fn aggregate_pk_shares(&mut self) -> Result<(), Error> {
        let mut pk_shares = Vec::new();
        for (user_id, user) in self.users.iter().enumerate() {
            if let UserStorage::PkShare(pk_share) = &user.storage {
                pk_shares.push(pk_share.clone());
            } else {
                return Err(Error::PkShareNotFound { user_id });
            }
        }
        self.ps.aggregate_pk_shares(&pk_shares);
        Ok(())
    }

    pub(crate) fn check_bsk_share_submission(&self) -> bool {
        self.users
            .iter()
            .all(|user| matches!(user.storage, UserStorage::BskShare(..)))
    }

    pub(crate) fn aggregate_bsk_shares(&mut self) -> Result<Vec<ServerKeyShare>, Error> {
        let mut bsk_shares = vec![];
        for (user_id, user) in self.users.iter_mut().enumerate() {
            if let Some(bsk_share) = user.storage.get_bsk_share() {
                bsk_shares.push(bsk_share.clone());
            } else {
                return Err(Error::BskShareNotFound { user_id });
            }
        }
        self.ps.aggregate_bs_key_shares::<PrimeRing>(&bsk_shares);
        Ok(bsk_shares)
    }

    pub(crate) fn create_task(
        &mut self,
        initiator: UserId,
        required_inputs: Vec<UserId>,
        initiator_input: Cipher,
    ) -> TaskId {
        let task_id = self.next_task_id;
        self.next_task_id += 1;
        let task = Task::new(task_id, initiator, required_inputs, initiator_input);
        self.task_queue.push_back(task);
        task_id
    }

    pub(crate) fn get_task(&mut self, task_id: TaskId) -> Result<&mut Task, Error> {
        self.task_queue
            .iter_mut()
            .find(|task| task.id == task_id)
            .ok_or(Error::TaskNotFound { task_id })
    }

    pub(crate) fn get_tasks_for_user(&self, _user_id: UserId) -> Vec<&Task> {
        self.task_queue.iter().collect()
    }

    pub(crate) fn add_input_to_task(
        &mut self,
        task_id: TaskId,
        user_id: UserId,
        input: Cipher,
    ) -> Result<(), Error> {
        let task = self.get_task(task_id)?;
        task.add_input(user_id, input)?;
        if task.is_ready_to_run() {
            task.status = TaskStatus::ReadyToRun;
        }
        Ok(())
    }

    pub(crate) fn complete_task(
        &mut self,
        task_id: TaskId,
        decryptables: Vec<Decryptable>,
    ) -> Result<(), Error> {
        let task = self.get_task(task_id)?;
        task.decryptables = decryptables;
        task.status = TaskStatus::WaitingDecryptionShares;
        Ok(())
    }

    pub(crate) fn get_next_ready_task(&mut self) -> Option<TaskId> {
        self.task_queue
            .iter()
            .find(|task| task.status == TaskStatus::ReadyToRun)
            .map(|task| task.id)
    }

    pub fn get_decryptables_for_user(&self, user_id: UserId) -> Vec<(TaskId, &Decryptable)> {
        self.task_queue
            .iter()
            .filter(|task| task.status == TaskStatus::WaitingDecryptionShares)
            .flat_map(|task| {
                task.get_decryptables_for_user(user_id)
                    .into_iter()
                    .map(move |d| (task.id, d))
            })
            .collect()
    }

    pub fn submit_decryption_share(
        &mut self,
        task_id: TaskId,
        decryptable_id: usize,
        user_id: UserId,
        share: DecryptionShare,
    ) -> Result<(), Error> {
        let task = self.get_task(task_id)?;

        println!(
            "User {} submitted decryption share for task {} and decryptable id {}",
            user_id, task_id, decryptable_id
        );

        if task.status != TaskStatus::WaitingDecryptionShares {
            return Err(Error::WrongTaskState {
                task_id,
                expected: TaskStatus::WaitingDecryptionShares,
                got: task.status.clone(),
            });
        }

        let decryptable = task
            .decryptables
            .iter_mut()
            .find(|d| d.id == decryptable_id)
            .ok_or(Error::DecryptableNotFound {
                task_id,
                decryptable_id,
            })?;

        if !decryptable.should_contribute(user_id) {
            return Err(Error::UnexpectedDecryptionShare { user_id });
        }

        decryptable.add_decryption_share(user_id, share);

        // Check if the task is complete
        if task.decryptables.iter().all(|d| d.is_complete) {
            task.status = TaskStatus::Done;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct UserRecord {
    pub(crate) id: UserId,
    pub(crate) storage: UserStorage,
}

#[derive(Debug, Clone)]
pub(crate) enum UserStorage {
    Empty,
    PkShare(Vec<u8>),
    BskShare(Box<Vec<u8>>),
}

impl UserStorage {
    pub(crate) fn get_bsk_share(&self) -> Option<&Vec<u8>> {
        match self {
            Self::BskShare(bsk_share) => Some(bsk_share),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub(crate) struct PkShareSubmission {
    pub(crate) user_id: UserId,
    pub(crate) pk_share: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub(crate) struct BskShareSubmission {
    pub(crate) user_id: UserId,
    pub(crate) bsk_share: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub(crate) struct CipherSubmission {
    pub(crate) user_id: UserId,
    pub(crate) cipher: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub(crate) struct CreateTaskSubmission {
    pub(crate) initiator: UserId,
    pub(crate) required_inputs: Vec<UserId>,
    pub(crate) initiator_input: Cipher,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub(crate) struct TaskInputSubmission {
    pub(crate) task_id: TaskId,
    pub(crate) user_id: UserId,
    pub(crate) input: Cipher,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub(crate) struct DecryptionShareSubmission {
    pub(crate) task_id: TaskId,
    pub(crate) decryptable_id: usize,
    pub(crate) user_id: UserId,
    pub(crate) share: DecryptionShare,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) enum Visibility {
    Public,
    Designated(UserId),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct Decryptable {
    pub(crate) id: usize,
    pub(crate) vis: Visibility,
    pub(crate) word: Word,
    shares: HashMap<UserId, DecryptionShare>,
    n_users: usize,
    /// Do we have all decryption shares required?
    pub(crate) is_complete: bool,
}

impl Decryptable {
    fn new(id: usize, n_users: usize, word: Word, vis: Visibility) -> Self {
        Self {
            id,
            vis,
            word,
            shares: HashMap::default(),
            n_users,
            is_complete: false,
        }
    }

    pub(crate) fn should_contribute(&self, user_id: UserId) -> bool {
        match self.vis {
            Visibility::Public => true,
            Visibility::Designated(id) => id != user_id,
        }
    }

    pub(crate) fn get_shares(&self) -> Vec<DecryptionShare> {
        self.shares.values().cloned().collect()
    }

    fn add_decryption_share(&mut self, user_id: UserId, share: DecryptionShare) {
        self.shares.insert(user_id, share);

        self.is_complete = match self.vis {
            Visibility::Public => self.shares.len() == self.n_users,
            Visibility::Designated(_) => self.shares.len() == self.n_users - 1,
        }
    }
}

pub(crate) struct DecryptableBuilder {
    n_users: usize,
    next_id: usize,
}

impl DecryptableBuilder {
    pub(crate) fn new(n_users: usize) -> Self {
        Self {
            n_users,
            next_id: 0,
        }
    }

    pub(crate) fn new_public(&mut self, word: Word) -> Decryptable {
        let id = self.next_id;
        self.next_id += 1;
        Decryptable::new(id, self.n_users, word, Visibility::Public)
    }

    pub(crate) fn new_designated(&mut self, word: Word, user_id: UserId) -> Decryptable {
        let id = self.next_id;
        self.next_id += 1;
        Decryptable::new(id, self.n_users, word, Visibility::Designated(user_id))
    }
}
