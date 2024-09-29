use crate::phantom::{function_bit, Server as PhantomServer};
use crate::types::{
    AnnotatedDecryptionShare, BskShareSubmission, Cipher, CipherSubmission, CreateTaskSubmission,
    DecryptionShareSubmission, Error, ErrorResponse, MutexServerStorage, ParamCRS,
    PkShareSubmission, ServerState, ServerStorage, Task, TaskId, TaskInputSubmission, UserId,
    UserStorage,
};

use itertools::Itertools;
use phantom_zone_evaluator::boolean::fhew::param::I_4P;
use phantom_zone_evaluator::boolean::FheBool;
use rocket::serde::json::Json;
use rocket::serde::msgpack::MsgPack;
use rocket::{get, post, routes};
use rocket::{Build, Rocket, State};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::task;

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
    channels: &State<Arc<ComputationChannels>>,
) -> Result<Json<()>, ErrorResponse> {
    let mut ss = ss.lock().await;

    ss.ensure(ServerState::ReadyForInputs)?;

    let CipherSubmission { user_id, cipher } = submission.0;

    ss.accept_cipher(user_id, cipher)?;

    if ss.is_ready_for_computation() {
        let ciphers = ss.get_ciphers_for_computation();
        println!("Starting computation with {} ciphers", ciphers.len());

        // Send ciphers to the background computation task
        if let Err(e) = channels.input_sender.send(ciphers).await {
            return Err(Error::ComputationErr {
                reason: e.to_string(),
            }
            .into());
        }
    }

    Ok(Json(()))
}

/// Create a new task
#[post("/create_task", data = "<submission>", format = "msgpack")]
async fn create_task(
    submission: MsgPack<CreateTaskSubmission>,
    ss: &State<MutexServerStorage>,
) -> Result<Json<TaskId>, ErrorResponse> {
    let mut ss = ss.lock().await;
    let CreateTaskSubmission {
        initiator,
        required_inputs,
        initiator_input,
    } = submission.0;
    let task_id = ss.create_task(initiator, required_inputs, initiator_input);
    Ok(Json(task_id))
}

/// Get tasks for a user
#[get("/tasks/<user_id>")]
async fn get_tasks_for_user(
    user_id: UserId,
    ss: &State<MutexServerStorage>,
) -> Result<Json<Vec<Task>>, ErrorResponse> {
    let ss = ss.lock().await;
    let tasks = ss.get_tasks_for_user(user_id);
    Ok(Json(tasks.into_iter().cloned().collect()))
}

/// Submit input for a task
#[post("/submit_task_input", data = "<submission>", format = "msgpack")]
async fn submit_task_input(
    submission: MsgPack<TaskInputSubmission>,
    ss: &State<MutexServerStorage>,
) -> Result<Json<()>, ErrorResponse> {
    let mut ss = ss.lock().await;
    let TaskInputSubmission {
        task_id,
        user_id,
        input,
    } = submission.0;
    ss.add_input_to_task(task_id, user_id, input)?;
    Ok(Json(()))
}

pub struct ComputationChannels {
    input_sender: mpsc::Sender<Vec<Cipher>>,
    output_receiver: mpsc::Receiver<Vec<Cipher>>,
}

async fn background_computation(
    mut input_receiver: mpsc::Receiver<Vec<Cipher>>,
    ss: Arc<MutexServerStorage>,
) {
    while let Some(task_id) = input_receiver.recv().await {
        let mut ss = ss.lock().await;
        let task = ss.get_task(task_id).unwrap();

        // Perform the FHE computation here
        println!("Performing computation for task {}", task_id);

        let ps = &ss.ps;
        let inputs: Vec<Vec<FheBool<_>>> = task
            .inputs
            .values()
            .map(|cipher| ps.deserialize_cts_bits(cipher))
            .collect();

        let [user_1_input, user_2_input] = deserialized_cts.try_into().unwrap();
        let [a, b]: [FheBool<_>; 2] = user_1_input.try_into().unwrap();
        let [c, d]: [FheBool<_>; 2] = user_2_input.try_into().unwrap();
        let g: FheBool<_> = function_bit(&a, &b, &c, &d);
        // For now, we'll just simulate a computation by waiting and returning the input
        // Should be decryptables
        let g = ps.serialize_cts_bits(&[g]);
        let result = vec![g.clone(), g];

        // Send the result
        if let Err(e) = output_sender.send(result).await {
            eprintln!("Failed to send computation result: {}", e);
        }

        // Create decryptables from the result
        let decryptables = vec![]; // Replace with actual decryptables
        ss.complete_task(task_id, decryptables).unwrap();
    }
}

pub fn rocket(n_users: usize) -> Rocket<Build> {
    let param = I_4P;
    let (input_sender, input_receiver) = mpsc::channel(100);
    let (output_sender, output_receiver) = mpsc::channel(100);

    let computation_channels = ComputationChannels {
        input_sender,
        output_receiver,
    };

    let ss = Arc::new(MutexServerStorage::new(Mutex::new(ServerStorage::new(
        param, n_users,
    ))));

    // Spawn the background computation task
    task::spawn(background_computation(input_receiver, ss.clone()));

    rocket::build()
        .manage(ss)
        .manage(Arc::new(computation_channels))
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
                create_task,
                get_tasks_for_user,
                submit_task_input,
            ],
        )
}
