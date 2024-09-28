use crate::types::{
    AnnotatedDecryptionShare, BskShareSubmission, CipherSubmission, DecryptionShareSubmission,
    Error, ErrorResponse, MutexServerStorage, ParamCRS, PkShareSubmission, ServerState,
    ServerStorage, UserId, UserStorage,
};

use phantom_zone_evaluator::boolean::fhew::param::I_4P;
use rocket::serde::json::Json;
use rocket::serde::msgpack::MsgPack;
use rocket::{get, post, routes};
use rocket::{Build, Rocket, State};
use tokio::sync::Mutex;

#[get("/param")]
pub(crate) async fn get_param(ss: &State<MutexServerStorage>) -> Json<ParamCRS> {
    let ss = ss.lock().await;
    Json(ss.get_param_crs())
}

#[post("/register")]
async fn register(ss: &State<MutexServerStorage>) -> Result<Json<usize>, ErrorResponse> {
    let mut ss = ss.lock().await;
    ss.ensure(ServerState::ReadyForJoining)?;
    let user = ss.add_user();
    if ss.is_users_full() {
        ss.transit(ServerState::ReadyForPkShares);
    }
    Ok(Json(user))
}

/// Get the current server status
#[get("/status")]
async fn get_status(ss: &State<MutexServerStorage>) -> Result<Json<ServerState>, ErrorResponse> {
    let ss = ss.lock().await;
    Ok(Json(ss.state.clone()))
}

/// The user submits Public Key shares
#[post("/submit_pk_shares", data = "<submission>", format = "msgpack")]
async fn submit_pk_shares(
    submission: MsgPack<PkShareSubmission>,
    ss: &State<MutexServerStorage>,
) -> Result<Json<UserId>, ErrorResponse> {
    let mut ss = ss.lock().await;

    ss.ensure(ServerState::ReadyForPkShares)?;

    let PkShareSubmission { user_id, pk_share } = submission.0;

    let user = ss.get_user(user_id)?;
    user.storage = UserStorage::PkShare(pk_share);

    if ss.check_pk_share_submission() {
        ss.aggregate_pk_shares()?;
        ss.transit(ServerState::ReadyForBskShares);
    }

    Ok(Json(user_id))
}

/// The user acquires the aggregated public key
#[get("/get_aggregated_pk")]
async fn get_aggregated_pk(ss: &State<MutexServerStorage>) -> Result<Json<Vec<u8>>, ErrorResponse> {
    let ss = ss.lock().await;

    ss.ensure(ServerState::ReadyForBskShares)?;

    // Serialize the aggregated public key
    let aggregated_pk = ss.ps.serialize_pk();

    Ok(Json(aggregated_pk))
}

/// The user submits Server key shares
#[post("/submit_bsks", data = "<submission>", format = "msgpack")]
async fn submit_bsks(
    submission: MsgPack<BskShareSubmission>,
    ss: &State<MutexServerStorage>,
) -> Result<Json<UserId>, ErrorResponse> {
    let mut ss = ss.lock().await;

    ss.ensure(ServerState::ReadyForBskShares)?;

    let BskShareSubmission { user_id, bsk_share } = submission.0;

    let user = ss.get_user(user_id)?;
    user.storage = UserStorage::BskShare(Box::new(bsk_share));

    if ss.check_bsk_share_submission() {
        ss.transit(ServerState::ReadyForInputs);
        println!("Derive bootstrap key");
        ss.aggregate_bsk_shares()?;
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

/// The user submits a cipher
#[post("/submit_cipher", data = "<submission>", format = "msgpack")]
async fn submit_cipher(
    submission: MsgPack<CipherSubmission>,
    ss: &State<MutexServerStorage>,
) -> Result<Json<()>, ErrorResponse> {
    let mut ss = ss.lock().await;

    ss.ensure(ServerState::ReadyForInputs)?;

    let CipherSubmission { user_id, cipher } = submission.0;

    ss.submit_cipher(user_id, cipher)?;

    if ss.is_ready_for_computation() {
        // Trigger computation
        let ciphers = ss.get_ciphers_for_computation();
        // TODO: Perform actual computation with ciphers
        println!("Starting computation with {} ciphers", ciphers.len());
    }

    Ok(Json(()))
}

pub fn rocket(n_users: usize) -> Rocket<Build> {
    let param = I_4P;
    rocket::build()
        .manage(MutexServerStorage::new(Mutex::new(ServerStorage::new(
            param, n_users,
        ))))
        .mount(
            "/",
            routes![
                get_param,
                register,
                get_status,
                submit_pk_shares,
                get_aggregated_pk,
                submit_bsks,
                submit_decryption_shares,
                get_decryption_share,
                submit_cipher,
            ],
        )
}
