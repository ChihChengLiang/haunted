use crate::{
    circuit::CircuitId,
    phantom::PhantomCt,
    server::ServerState,
    worker::{WorkerKey, WorkerMessage},
    Result,
};
use anyhow::bail;
use axum::{
    extract::{
        ws::{Message, WebSocket},
        ConnectInfo, State, WebSocketUpgrade,
    },
    response::IntoResponse,
    routing::any,
    Router,
};
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

pub type TaskId = uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TaskRequest {
    pub task_id: TaskId,
    pub circuit_id: CircuitId,
    pub inputs: Vec<PhantomCt>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TaskResponse {
    pub task_id: TaskId,
    pub outputs: Vec<PhantomCt>,
}

#[derive(Debug)]
struct WorkerState {
    tx: UnboundedSender<WorkerMessage>,
    scheduled: HashMap<TaskId, TaskRequest>,
}

impl WorkerState {
    fn new(tx: UnboundedSender<WorkerMessage>) -> Self {
        Self {
            tx,
            scheduled: HashMap::new(),
        }
    }

    fn set_key(&mut self, key: WorkerKey) {
        self.tx.send(WorkerMessage::SetKey(Box::new(key))).unwrap();
    }

    fn send_task(&mut self, request: TaskRequest) {
        self.scheduled.insert(request.task_id, request.clone());
        self.tx.send(WorkerMessage::TaskRequest(request)).unwrap();
    }
}

#[derive(Debug, Default)]
pub struct SchedulerState {
    task_counter: usize,
    workers: Vec<WorkerState>,
}

impl SchedulerState {
    fn register(&mut self, tx: UnboundedSender<WorkerMessage>, key: Option<WorkerKey>) {
        let mut worker = WorkerState::new(tx);
        if let Some(key) = key {
            worker.set_key(key);
        }
        self.workers.push(worker);

        tracing::debug!("registered, current worker count: {}", self.workers.len());
    }

    fn unregister(&mut self, tx: UnboundedSender<WorkerMessage>) {
        let idx = self
            .workers
            .iter()
            .position(|worker| worker.tx.same_channel(&tx))
            .unwrap();
        let worker = self.workers.remove(idx);

        tracing::debug!("unregistered, current worker count: {}", self.workers.len());

        worker.scheduled.into_values().for_each(|request| {
            let _ = self.schedule_task_request(request);
        })
    }

    fn finish_task(&mut self, task_id: TaskId) {
        self.workers.iter_mut().for_each(|worker| {
            worker.scheduled.remove(&task_id);
        });

        tracing::debug!("finished task {task_id:?}");
    }

    pub fn set_key(&mut self, key: WorkerKey) {
        self.workers
            .iter_mut()
            .for_each(|worker| worker.set_key(key.clone()));
    }

    pub fn schedule_task_request(&mut self, request: TaskRequest) -> Result<()> {
        if self.workers.is_empty() {
            tracing::error!("failed to schedule task because no worker available");
            bail!("no worker available");
        }

        let idx = self.task_counter % self.workers.len();
        let task_id = request.task_id;
        self.task_counter += 1;
        self.workers[idx].send_task(request);

        tracing::debug!("scheduled task {task_id:?} to workers[{idx}]");

        Ok(())
    }
}

pub fn router() -> Router<Arc<Mutex<ServerState>>> {
    Router::new().route("/ws", any(ws))
}

async fn ws(
    State(state): State<Arc<Mutex<ServerState>>>,
    wsu: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    wsu.on_upgrade(move |mut ws| async move {
        if let Err(err) = ws.send(Message::Ping(Vec::new())).await {
            tracing::warn!("failed to send ping, {err}");
            return;
        }
        if let Some(Err(err)) = ws.recv().await {
            tracing::warn!("failed to receive pong, {err}");
            return;
        }
        tracing::debug!("connected to worker {addr}");

        let (ws_tx, ws_rx) = ws.split();

        let (tx, rx) = unbounded_channel();
        {
            let mut state = state.lock().unwrap();
            let key = state.app.worker_key();
            state.scheduler.register(tx.clone(), key);
        }

        tokio::select! {
            _ = tokio::spawn(handle_request(ws_tx, rx)) => {},
            _ = tokio::spawn(handle_response(state.clone(), ws_rx)) => {},
        };

        tracing::debug!("unconnected to worker {addr}");

        let mut state = state.lock().unwrap();
        state.scheduler.unregister(tx);
    })
}

async fn handle_request(
    mut ws_tx: SplitSink<WebSocket, Message>,
    mut rx: UnboundedReceiver<WorkerMessage>,
) {
    while let Some(request) = rx.recv().await {
        let bytes = bincode::serialize(&request).unwrap();
        if let Err(err) = ws_tx.send(Message::Binary(bytes)).await {
            tracing::error!("failed to send task request to worker, {err}");
            break;
        }
    }
}

async fn handle_response(state: Arc<Mutex<ServerState>>, mut ws_rx: SplitStream<WebSocket>) {
    while let Some(Ok(msg)) = ws_rx.next().await {
        match msg {
            Message::Binary(bytes) => {
                let worker_msg: WorkerMessage = bincode::deserialize(&bytes).unwrap();
                match worker_msg {
                    WorkerMessage::TaskResponse(response) => {
                        let mut state = state.lock().unwrap();
                        state.scheduler.finish_task(response.task_id);
                        state.app.handle_task(response);
                    }
                    _ => tracing::warn!("received unexpected worker msg {worker_msg:?}"),
                }
            }
            Message::Close(_) => break,
            _ => tracing::warn!("received unexpected msg {msg:?}"),
        }
    }
}
