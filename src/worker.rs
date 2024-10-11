use crate::{
    phantom::{
        PhantomBool, PhantomBsKey, PhantomEvaluator, PhantomOps, PhantomParam, PhantomRpKey,
    },
    server::{
        app::BS_KEY_SIZE,
        scheduler::{TaskRequest, TaskResponse},
    },
    Result,
};
use anyhow::bail;
use core::time::Duration;
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::{
    net::TcpStream,
    sync::{broadcast, Mutex, RwLock},
    time::sleep,
};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{protocol::WebSocketConfig, Message},
    MaybeTlsStream, WebSocketStream,
};

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerMessage {
    SetKey(Box<WorkerKey>),
    TaskRequest(TaskRequest),
    TaskResponse(TaskResponse),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerKey {
    pub param: PhantomParam,
    pub rp_key: PhantomRpKey,
    pub bs_key: PhantomBsKey,
}

struct Worker {
    // ops: PhantomOps,
    // rp_key: RingPackingKeyOwned<u64>,
    evaluator: PhantomEvaluator,
}

impl Worker {
    fn new(key: &WorkerKey) -> Self {
        let ops = PhantomOps::new(key.param);
        let evaluator = ops.evaluator(&key.bs_key);
        Self {
            // ops,
            // rp_key: key.rp_key.clone(),
            evaluator,
        }
    }

    fn process_task(&self, request: TaskRequest) -> TaskResponse {
        let inputs = request
            .inputs
            .into_iter()
            .map(|input| PhantomBool::new(&self.evaluator, input))
            .collect_vec();
        let outputs = {
            let outputs = request.circuit_id.evaluate(&inputs);
            outputs
                .into_iter()
                .map(|input| input.into_ct())
                .collect_vec()
        };
        TaskResponse {
            task_id: request.task_id,
            outputs,
        }
    }
}

pub async fn run(server_uri: impl ToString, mut shutdown_rx: broadcast::Receiver<()>) {
    let server_uri = server_uri.to_string();

    loop {
        let ws = tokio::select! {
            Ok(_) = shutdown_rx.recv() => break,
            Ok(ws) = tokio::spawn(connect_until_ok(server_uri.clone())) => ws,
        };

        let (ws_tx, mut ws_rx) = ws.split();
        let ws_tx = Arc::new(Mutex::new(ws_tx));

        if let Some(Err(err)) = ws_rx.next().await {
            tracing::error!("failed to receive ping, {err}");
            return;
        }

        tokio::select! {
            Ok(_) = shutdown_rx.recv() => {
                let _ = ws_tx.lock().await.send(Message::Close(None)).await;
                break
            },
            Ok(result) = tokio::spawn(handle_task(ws_tx.clone(), ws_rx)) => {
                if let Err(err) = result {
                    tracing::error!("{err}");
                }
            },
        };
    }
}

async fn connect_until_ok(server_uri: String) -> WebSocketStream<MaybeTlsStream<TcpStream>> {
    tracing::debug!("connecting to server {server_uri}");
    let config = WebSocketConfig {
        max_frame_size: Some(BS_KEY_SIZE),
        ..Default::default()
    };
    loop {
        match connect_async_with_config(&server_uri, Some(config), false).await {
            Ok((ws, _)) => {
                tracing::debug!("connected to server {server_uri}");
                break ws;
            }
            Err(err) => {
                tracing::warn!("failed to connect to server {server_uri}, {err}");
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        }
    }
}

async fn handle_task(
    ws_tx: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
    mut ws_rx: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
) -> Result<()> {
    let worker = Arc::new(RwLock::new(None));
    while let Some(msg) = ws_rx.next().await {
        match msg {
            Ok(Message::Binary(bytes)) => {
                let msg: WorkerMessage = bincode::deserialize(&bytes).unwrap();
                match msg {
                    WorkerMessage::SetKey(key) => {
                        *worker.write().await = Some(Worker::new(&key));
                        tracing::debug!("succeeded to set key")
                    }
                    WorkerMessage::TaskRequest(request) => {
                        let Some(worker) = &*worker.read().await else {
                            bail!("unexpected task before set key");
                        };
                        let response = WorkerMessage::TaskResponse(worker.process_task(request));
                        let bytes = bincode::serialize(&response).unwrap();
                        if let Err(err) = ws_tx.lock().await.send(Message::Binary(bytes)).await {
                            bail!("failed to send task response, {err}");
                        }
                    }
                    _ => tracing::warn!("received unexpected worker msg {msg:?}"),
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(msg) => tracing::warn!("received unexpected msg {msg}"),
            Err(err) => bail!("failed to receive message, {err}"),
        }
    }
    Ok(())
}
