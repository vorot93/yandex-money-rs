use http::StatusCode;
use log::*;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use snafu::*;
use std::{collections::HashMap, fmt::Debug, future::Future, pin::Pin, sync::Arc};

pub type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Snafu)]
pub enum Error {
    NetworkError {
        source: StdError,
        backtrace: Backtrace,
    },
    ParseError {
        source: StdError,
        backtrace: Backtrace,
    },
}

impl Error {
    pub fn from_network_error<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        NetworkError.into_error(Box::new(error))
    }

    pub fn from_parse_error<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        ParseError.into_error(Box::new(error))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", untagged)]
pub enum Rsp<T> {
    Error { error: String },
    OK(T),
}

pub trait Transport: Debug + Send + Sync + 'static {
    fn call(
        &self,
        endpoint: &'static str,
        params: &HashMap<&str, String>,
    ) -> Pin<Box<dyn Future<Output = Result<String, StdError>> + Send + 'static>>;

    fn get_redirect(
        &self,
        endpoint: &'static str,
        params: &HashMap<&str, String>,
    ) -> Pin<Box<dyn Future<Output = Result<String, StdError>> + Send + 'static>>;
}

#[derive(Debug)]
pub struct RemoteCaller {
    pub http_client: reqwest::Client,
    pub addr: String,
    pub bearer: Option<String>,
}

impl Transport for RemoteCaller {
    fn call(
        &self,
        endpoint: &'static str,
        params: &HashMap<&str, String>,
    ) -> Pin<Box<dyn Future<Output = Result<String, StdError>> + Send + 'static>> {
        let client = self.http_client.clone();
        let uri = format!("{}/{}", self.addr, endpoint);
        let params_trace = format!("{:?}", params);

        let mut req = client.post(&uri).form(params);
        if let Some(bearer) = self.bearer.as_ref() {
            req = req.bearer_auth(&bearer);
        }

        Box::pin(async move {
            trace!(
                "Sending request to endpoint {} with params: {}",
                endpoint,
                params_trace
            );

            let rsp = req.send().await?;
            let err = rsp.error_for_status_ref().err();

            let data = rsp.text().await?;

            trace!("Received HTTP response: {}", data);

            if let Some(err) = err {
                return Err(format!("Received error {} with data: {}", err, data).into());
            }

            Ok(data)
        })
    }

    fn get_redirect(
        &self,
        endpoint: &'static str,
        params: &HashMap<&str, String>,
    ) -> Pin<Box<dyn Future<Output = Result<String, StdError>> + Send + 'static>> {
        let uri = format!("{}/{}", self.addr, endpoint);

        let redirect_url = Arc::new(Mutex::new(None));
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::custom({
                let redirect_url = redirect_url.clone();
                move |attempt| {
                    *redirect_url.lock() = Some(attempt.url().to_string());
                    attempt.stop()
                }
            }))
            .build()
            .map(|client| client.post(&uri).form(params));

        let params_trace = format!("{:?}", params);

        Box::pin(async move {
            trace!(
                "Sending request to endpoint {} with params: {}",
                uri,
                params_trace
            );

            let client = client.map_err(Error::from_network_error)?;
            let rsp = client.send().await?;

            match rsp.status() {
                StatusCode::FOUND => Ok((*redirect_url.lock())
                    .clone()
                    .expect("always filled by redirect policy; qed")),
                other => Err(format!("Unexpected status code: {}", other).into()),
            }
        })
    }
}

#[derive(Clone, Debug)]
pub struct CallerWrapper {
    pub transport: Arc<dyn Transport>,
}

impl CallerWrapper {
    pub fn call<T>(
        &self,
        method: &'static str,
        params: &HashMap<&str, String>,
    ) -> impl Future<Output = Result<Rsp<T>, Error>> + Send + 'static
    where
        T: for<'de> Deserialize<'de> + Send + 'static,
    {
        let c = self.transport.call(method, params);
        async move {
            Ok(serde_json::from_str(&c.await.context(NetworkError)?)
                .map_err(Error::from_parse_error)?)
        }
    }

    pub fn call_empty(
        &self,
        method: &'static str,
        params: &HashMap<&str, String>,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'static {
        let c = self.transport.call(method, params);

        async move {
            c.await.context(NetworkError)?;

            Ok(())
        }
    }

    pub fn get_redirect(
        &self,
        endpoint: &'static str,
        params: &HashMap<&str, String>,
    ) -> impl Future<Output = Result<String, Error>> + Send + 'static {
        let s = self.transport.get_redirect(endpoint, params);

        async move { Ok(s.await.context(NetworkError)?) }
    }
}
