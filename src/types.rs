use crate::phantom::Server as PhantomServer;
use itertools::Itertools;
use phantom_zone_evaluator::boolean::fhew::prelude::*;
use phantom_zone_evaluator::boolean::FheBool;
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
/// Decryption share with output id
pub type AnnotatedDecryptionShare = (usize, DecryptionShare);
pub type ServerKeyShare = Vec<u8>;
pub type ParamCRS = (FhewBoolMpiParam, FhewBoolMpiCrs<StdRng>);
pub type Cipher = Vec<u8>;

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
    #[error("The ciphertext from user #{user_id} not found")]
    CipherNotFound { user_id: UserId },
    #[error("Decryption share of {output_id} from user {user_id} not found")]
    DecryptionShareNotFound { output_id: usize, user_id: UserId },
    #[error("Output not ready")]
    OutputNotReady,
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
            Error::WrongServerState { .. } | Error::CipherNotFound { .. } => {
                ErrorResponse::ServerError(error.to_string())
            }
            Error::PkShareNotFound { .. }
            | Error::BskShareNotFound { .. }
            | Error::DecryptionShareNotFound { .. }
            | Error::UnregisteredUser { .. }
            | Error::OutputNotReady => ErrorResponse::NotFoundError(error.to_string()),
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
    n_users: usize,
    pub(crate) ps: PhantomServer<NoisyPrimeRing, NonNativePowerOfTwo>,
    pub(crate) state: ServerState,
    pub(crate) users: Vec<UserRecord>,
    cipher_queues: Vec<VecDeque<Cipher>>,
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
            cipher_queues: vec![],
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
        self.cipher_queues.push(VecDeque::new());
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
                user.storage = UserStorage::DecryptionShare(None);
            } else {
                return Err(Error::BskShareNotFound { user_id });
            }
        }
        self.ps.aggregate_bs_key_shares::<PrimeRing>(&bsk_shares);
        Ok(bsk_shares)
    }

    pub(crate) fn accept_cipher(&mut self, user_id: UserId, cipher: Cipher) -> Result<(), Error> {
        self.cipher_queues.get_mut(user_id).ok_or(Error::UnregisteredUser { user_id })?.push_back(cipher);
        Ok(())
    }

    pub(crate) fn is_ready_for_computation(&self) -> bool {
        self.cipher_queues.iter().all(|queue| !queue.is_empty())
    }

    pub(crate) fn get_ciphers_for_computation(&mut self) -> Vec<Cipher> {
        self.cipher_queues.iter_mut().map(|queue| queue.pop_front().unwrap()).collect()
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
    DecryptionShare(Option<Vec<AnnotatedDecryptionShare>>),
}

impl UserStorage {
    pub(crate) fn get_bsk_share(&self) -> Option<&Vec<u8>> {
        match self {
            Self::BskShare(bsk_share) => Some(bsk_share),
            _ => None,
        }
    }

    pub(crate) fn get_mut_decryption_shares(
        &mut self,
    ) -> Option<&mut Option<Vec<AnnotatedDecryptionShare>>> {
        match self {
            Self::DecryptionShare(ds) => Some(ds),
            _ => None,
        }
    }
}

/// ([`Word`] index, user_id) -> decryption share
pub type DecryptionSharesMap = HashMap<(usize, UserId), DecryptionShare>;

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
pub(crate) struct DecryptionShareSubmission {
    pub(crate) user_id: UserId,
    /// The user sends decryption share for each [`Word`].
    pub(crate) decryption_shares: Vec<AnnotatedDecryptionShare>,
}

pub type DecryptableID = usize;

#[derive(Debug, Serialize, Deserialize)]
enum Visibility {
    Public,
    Designated(UserId),
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Decryptable {
    pub(crate) id: usize,
    vis: Visibility,
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

    fn add_decryption_share(&mut self, user_id: UserId, share: DecryptionShare) {
        self.shares.insert(user_id, share);
        if self.shares.len() == self.n_users {
            self.is_complete = true;
        }
    }
}

pub(crate) struct DecryptableManager {
    n_users: usize,
    decryptables: Vec<Decryptable>,
}

impl DecryptableManager {
    pub(crate) fn new(n_users: usize) -> Self {
        Self {
            n_users,
            decryptables: vec![],
        }
    }
    fn add_decryptable(&mut self, word: Word, vis: Visibility) -> DecryptableID {
        let id = self.decryptables.len();
        let d = Decryptable::new(id, self.n_users, word, vis);
        self.decryptables.push(d);
        id
    }

    pub(crate) fn add_public(&mut self, word: Word) -> DecryptableID {
        self.add_decryptable(word, Visibility::Public)
    }

    pub(crate) fn add_designated(&mut self, word: Word, user_id: UserId) -> DecryptableID {
        self.add_decryptable(word, Visibility::Designated(user_id))
    }

    pub(crate) fn list_decryption_duties(&self, user_id: UserId) -> Vec<Word> {
        self.decryptables
            .iter()
            .filter(|d| !d.is_complete)
            .filter(|d| match d.vis {
                Visibility::Public => true,
                Visibility::Designated(designated_id) => user_id != designated_id,
            })
            .map(|d| d.word.clone())
            .collect_vec()
    }
}
