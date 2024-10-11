use crate::{
    phantom::{PhantomCrs, PhantomParam},
    server::{app::AppState, scheduler::SchedulerState},
};
use axum::{extract::connect_info::IntoMakeServiceWithConnectInfo, Router};
use core::net::SocketAddr;
use std::sync::{Arc, Mutex};

pub mod app;
pub mod scheduler;
pub mod util;

#[derive(Debug)]
pub struct ServerState {
    pub app: AppState,
    pub scheduler: SchedulerState,
}

impl ServerState {
    pub fn new(param: PhantomParam, crs: PhantomCrs) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            app: AppState::new(param, crs),
            scheduler: Default::default(),
        }))
    }
}

pub fn router(
    state: Arc<Mutex<ServerState>>,
) -> IntoMakeServiceWithConnectInfo<Router, SocketAddr> {
    Router::new()
        .merge(app::router())
        .merge(scheduler::router())
        .with_state(state)
        .into_make_service_with_connect_info()
}

#[cfg(test)]
pub mod test {
    use crate::{
        phantom::{PhantomCrs, PhantomParam},
        server::{self, ServerState},
    };
    use std::net::SocketAddr;
    use tokio::{net::TcpListener, task::JoinHandle};

    pub const TEST_PARAM: PhantomParam = PhantomParam::I_4P_60;
    pub const TEST_CRS: PhantomCrs = PhantomCrs::new([0x42; 32]);

    pub async fn test_server() -> (JoinHandle<()>, SocketAddr) {
        let listener = TcpListener::bind("localhost:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        tracing::debug!("listening on {server_addr}");

        let state = ServerState::new(TEST_PARAM, TEST_CRS);
        let router = server::router(state);
        let handle = tokio::spawn(async { axum::serve(listener, router).await.unwrap() });
        (handle, server_addr)
    }
}
