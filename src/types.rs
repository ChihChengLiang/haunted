use itertools::Itertools;
use phantom_zone::{
    evaluator::NonInteractiveMultiPartyCrs,
    keys::CommonReferenceSeededNonInteractiveMultiPartyServerKeyShare, parameters::BoolParameters,
    Encryptor, FheBool, KeySwitchWithId, MultiPartyDecryptor, NonInteractiveSeededFheBools,
    SampleExtractor,
};
use rocket::serde::{Deserialize, Serialize};
use rocket::tokio::sync::Mutex;
use rocket::Responder;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fmt::Display;
use std::sync::Arc;
use thiserror::Error;

pub type ClientKey = phantom_zone::ClientKey;
pub type UserId = usize;

pub(crate) type Seed = [u8; 32];
pub(crate) type ServerKeyShare = CommonReferenceSeededNonInteractiveMultiPartyServerKeyShare<
    Vec<Vec<u64>>,
    BoolParameters<u64>,
    NonInteractiveMultiPartyCrs<Seed>,
>;
pub type Word = Vec<FheBool>;
pub(crate) type CircuitInput = Vec<Word>;
/// Decryption share for a word from one user.
pub type DecryptionShare = Vec<u64>;

/// Decryption share with output id
pub type AnnotatedDecryptionShare = (usize, DecryptionShare);

pub(crate) type EncryptedWord = NonInteractiveSeededFheBools<Vec<u64>, Seed>;

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("Wrong server state: expect {expect} but got {got}")]
    WrongServerState { expect: String, got: String },
    #[error("User #{user_id} is unregistered")]
    UnregisteredUser { user_id: usize },
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
            Error::DecryptionShareNotFound { .. }
            | Error::UnregisteredUser { .. }
            | Error::OutputNotReady => ErrorResponse::NotFoundError(error.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServerState {
    /// Users are allowed to join the computation
    ReadyForJoining,
    /// The number of user is determined now.
    /// We can now accept ciphertexts, which depends on the number of users.
    ReadyForInputs,
    ReadyForRunning,
    RunningFhe,
    CompletedFhe,
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

#[derive(Debug)]
pub(crate) struct ServerStorage {
    pub(crate) seed: Seed,
    pub(crate) state: ServerState,
    pub(crate) users: Vec<UserRecord>,
}

impl ServerStorage {
    pub(crate) fn new(seed: Seed) -> Self {
        Self {
            seed,
            state: ServerState::ReadyForJoining,
            users: vec![],
        }
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

    pub(crate) fn check_cipher_submission(&self) -> bool {
        self.users
            .iter()
            .all(|user| matches!(user.storage, UserStorage::Sks(..)))
    }

    pub(crate) fn get_sks(&mut self) -> Result<Vec<ServerKeyShare>, Error> {
        let mut server_key_shares = vec![];
        for (user_id, user) in self.users.iter_mut().enumerate() {
            if let Some(sks) = user.storage.get_cipher_sks() {
                server_key_shares.push(sks.clone());
                user.storage = UserStorage::DecryptionShare(None);
            } else {
                return Err(Error::CipherNotFound { user_id });
            }
        }
        Ok(server_key_shares)
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
    Sks(Box<ServerKeyShare>),
    DecryptionShare(Option<Vec<AnnotatedDecryptionShare>>),
}

impl UserStorage {
    pub(crate) fn get_cipher_sks(&self) -> Option<&ServerKeyShare> {
        match self {
            Self::Sks(sks) => Some(sks),
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
pub(crate) struct SksSubmission {
    pub(crate) user_id: UserId,
    pub(crate) sks: ServerKeyShare,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub(crate) struct DecryptionShareSubmission {
    pub(crate) user_id: UserId,
    /// The user sends decryption share for each [`Word`].
    pub(crate) decryption_shares: Vec<AnnotatedDecryptionShare>,
}

pub type DecryptableID = usize;

enum Visibility {
    Public,
    Designated(UserId),
}

struct Decryptable {
    vis: Visibility,
    word: Word,
    shares: HashMap<UserId, DecryptionShare>,
    n_users: usize,
    /// Do we have all decryption shares required?
    is_complete: bool,
}

impl Decryptable {
    fn new(n_users: usize, word: Word, vis: Visibility) -> Self {
        Self {
            vis,
            word,
            shares: HashMap::default(),
            n_users,
            is_complete: false,
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
        let d = Decryptable::new(self.n_users, word, vis);
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
