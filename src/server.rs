use crate::types::{
    AnnotatedDecryptionShare, DecryptionShareSubmission, Error, ErrorResponse, MutexServerStorage,
    Seed, ServerKeyShare, ServerState, ServerStorage, SksSubmission, UserId, UserStorage,
};
use phantom_zone::{
    aggregate_server_key_shares, set_common_reference_seed, set_parameter_set, ParameterSelector,
};
use rand::{thread_rng, RngCore};
use rocket::serde::json::Json;
use rocket::serde::msgpack::MsgPack;
use rocket::{get, post, routes};
use rocket::{Build, Rocket, State};
use tokio::sync::Mutex;

pub const PARAMETER: ParameterSelector = ParameterSelector::NonInteractiveLTE4Party;

pub(crate) fn derive_server_key(server_key_shares: &[ServerKeyShare]) {
    let server_key = aggregate_server_key_shares(server_key_shares);
    server_key.set_server_key();
}

#[get("/param")]
async fn get_param(ss: &State<MutexServerStorage>) -> Json<Seed> {
    let ss = ss.lock().await;
    Json(ss.seed)
}

#[post("/register")]
async fn register(ss: &State<MutexServerStorage>) -> Result<Json<usize>, ErrorResponse> {
    let mut ss = ss.lock().await;
    ss.ensure(ServerState::ReadyForJoining)?;
    let user = ss.add_user();
    Ok(Json(user))
}

/// The user submits Server key shares
#[post("/submit_sks", data = "<submission>", format = "msgpack")]
async fn submit_sks(
    submission: MsgPack<SksSubmission>,
    ss: &State<MutexServerStorage>,
) -> Result<Json<UserId>, ErrorResponse> {
    let mut ss = ss.lock().await;

    ss.ensure(ServerState::ReadyForInputs)?;

    let SksSubmission { user_id, sks } = submission.0;

    let user = ss.get_user(user_id)?;
    user.storage = UserStorage::Sks(Box::new(sks));

    if ss.check_cipher_submission() {
        ss.transit(ServerState::ReadyForInputs);
        let server_key_shares = ss.get_sks()?;
        set_parameter_set(PARAMETER);

        tokio::task::spawn_blocking(move || {
            rayon::ThreadPoolBuilder::new()
                .build_scoped(
                    // Initialize thread-local storage parameters
                    |thread| {
                        set_parameter_set(PARAMETER);
                        thread.run()
                    },
                    // Run parallel code under this pool
                    |pool| {
                        pool.install(|| {
                            println!("Derive server key");
                            // Long running, global variable change
                            derive_server_key(&server_key_shares);
                        })
                    },
                )
                .unwrap();
        });
    }

    Ok(Json(user_id))
}

/// The user submits the ciphertext
#[post("/submit_decryption_shares", data = "<submission>", format = "msgpack")]
async fn submit_decryption_shares(
    submission: MsgPack<DecryptionShareSubmission>,
    ss: &State<MutexServerStorage>,
) -> Result<Json<UserId>, ErrorResponse> {
    let DecryptionShareSubmission {
        user_id,
        decryption_shares,
    } = submission.0;
    let mut ss = ss.lock().await;
    let ds = ss
        .get_user(user_id)?
        .storage
        .get_mut_decryption_shares()
        .ok_or(Error::OutputNotReady)?;
    *ds = Some(decryption_shares);
    Ok(Json(user_id))
}

#[get("/decryption_share/<output_id>/<user_id>")]
async fn get_decryption_share(
    output_id: usize,
    user_id: UserId,
    ss: &State<MutexServerStorage>,
) -> Result<Json<AnnotatedDecryptionShare>, ErrorResponse> {
    let mut ss: tokio::sync::MutexGuard<ServerStorage> = ss.lock().await;
    let decryption_shares = ss
        .get_user(user_id)?
        .storage
        .get_mut_decryption_shares()
        .cloned()
        .ok_or(Error::OutputNotReady)?
        .ok_or(Error::DecryptionShareNotFound { output_id, user_id })?;
    Ok(Json(decryption_shares[output_id].clone()))
}

pub fn setup(seed: &Seed) {
    set_parameter_set(PARAMETER);
    set_common_reference_seed(*seed);
}

pub fn rocket() -> Rocket<Build> {
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);
    setup(&seed);

    rocket::build()
        .manage(MutexServerStorage::new(Mutex::new(ServerStorage::new(
            seed,
        ))))
        .mount(
            "/",
            routes![
                get_param,
                register,
                submit_sks,
                submit_decryption_shares,
                get_decryption_share,
            ],
        )
}
