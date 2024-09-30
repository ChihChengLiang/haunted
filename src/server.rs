use crate::phantom::function_bit;
use crate::types::{
    BskShareSubmission, CreateTaskSubmission, Decryptable, DecryptableBuilder,
    DecryptionShareSubmission, ErrorResponse, MutexServerStorage, ParamCRS, PkShareSubmission,
    ServerState, ServerStorage, Task, TaskId, TaskInputSubmission, UserId, UserStorage,
};

use phantom_zone_evaluator::boolean::{fhew::param::I_4P, FheBool};
use rocket::serde::json::Json;
use rocket::serde::msgpack::MsgPack;
use rocket::{get, post, routes, Build, Rocket, State};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task;
use tokio::time::sleep;

#[get("/param")]
async fn get_param(ss: &State<MutexServerStorage>) -> Json<ParamCRS> {
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
    let ss_clone = Arc::clone(&ss);
    let mut ss = ss.lock().await;

    ss.ensure(ServerState::ReadyForBskShares)?;

    let BskShareSubmission { user_id, bsk_share } = submission.0;

    let user = ss.get_user(user_id)?;
    user.storage = UserStorage::BskShare(Box::new(bsk_share));

    if ss.check_bsk_share_submission() {
        ss.transit(ServerState::ReadyForInputs);
        println!("Derive bootstrap key");
        ss.aggregate_bsk_shares()?;

        // Spawn the background computation task
        task::spawn(async move {
            background_computation(ss_clone).await;
        });
    }

    Ok(Json(user_id))
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

async fn background_computation(ss: MutexServerStorage) {
    let (ps, n_users) = {
        let ss = ss.lock().await;
        (ss.ps.clone(), ss.n_users)
    };
    let mut builder = DecryptableBuilder::new(n_users);
    loop {
        let task_to_process = {
            let mut ss = ss.lock().await;
            ss.get_next_ready_task()
        };

        if let Some(task_id) = task_to_process {
            let mut ss = ss.lock().await;
            let task = ss.get_task(task_id).unwrap();

            // Perform the FHE computation here
            println!("Performing computation for task {}", task_id);

            let inputs: Vec<Vec<FheBool<_>>> = task
                .inputs
                .values()
                .map(|cipher| ps.deserialize_cts_bits(cipher))
                .collect();

            let [user_1_input, user_2_input] = inputs.try_into().unwrap();
            let [a, b]: [FheBool<_>; 2] = user_1_input.try_into().unwrap();
            let [c, d]: [FheBool<_>; 2] = user_2_input.try_into().unwrap();
            let g: FheBool<_> = function_bit(&a, &b, &c, &d);
            // For now, we'll just simulate a computation by waiting and returning the input
            // Should be decryptables
            let g = ps.serialize_cts_bits(&[g]);

            // Create decryptables from the result
            let decryptables = vec![builder.new_public(g.clone()), builder.new_designated(g, 1)]; // Replace with actual decryptables
            ss.complete_task(task_id, decryptables).unwrap();
        } else {
            // No tasks ready, sleep for a bit before checking again
            sleep(Duration::from_millis(100)).await;
        }
    }
}

#[get("/decryptables/<user_id>")]
async fn get_decryptables_for_user(
    user_id: UserId,
    ss: &State<MutexServerStorage>,
) -> Result<Json<Vec<(TaskId, Decryptable)>>, ErrorResponse> {
    let ss = ss.lock().await;
    let decryptables = ss.get_decryptables_for_user(user_id);
    Ok(Json(
        decryptables
            .into_iter()
            .map(|(tid, d)| (tid, d.clone()))
            .collect(),
    ))
}

#[post("/submit_decryption_share", data = "<submission>", format = "msgpack")]
async fn submit_decryption_share(
    submission: MsgPack<DecryptionShareSubmission>,
    ss: &State<MutexServerStorage>,
) -> Result<Json<()>, ErrorResponse> {
    let mut ss = ss.lock().await;
    let DecryptionShareSubmission {
        task_id,
        decryptable_id,
        user_id,
        share,
    } = submission.0;
    ss.submit_decryption_share(task_id, decryptable_id, user_id, share)?;
    Ok(Json(()))
}

pub fn rocket(n_users: usize) -> Rocket<Build> {
    let param = I_4P;
    let ss = MutexServerStorage::new(Mutex::new(ServerStorage::new(param, n_users)));

    rocket::build().manage(ss).mount(
        "/",
        routes![
            get_param,
            register,
            get_status,
            submit_pk_shares,
            get_aggregated_pk,
            submit_bsks,
            create_task,
            get_tasks_for_user,
            submit_task_input,
            get_decryptables_for_user,
            submit_decryption_share,
        ],
    )
}
