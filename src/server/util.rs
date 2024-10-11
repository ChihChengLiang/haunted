use axum::{
    async_trait,
    body::Bytes,
    extract::{FromRequest, Request},
    response::{IntoResponse, Response},
};
use hyper::StatusCode;
use serde::{de::DeserializeOwned, Serialize};

pub struct Bincode<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for Bincode<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(internal_server_error)?;
        Ok(Self(bincode::deserialize(&bytes).map_err(bad_request)?))
    }
}

impl<T> IntoResponse for Bincode<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        match bincode::serialize(&self.0) {
            Ok(bytes) => bytes.into_response(),
            Err(err) => internal_server_error(err).into_response(),
        }
    }
}

pub fn bad_request(msg: impl ToString) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, msg.to_string())
}

pub fn internal_server_error(msg: impl ToString) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, msg.to_string())
}
