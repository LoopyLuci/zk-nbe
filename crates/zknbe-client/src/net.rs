//! Minimal JSON-over-HTTP transport.

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt;
use std::time::Duration;
use zknbe_core::proto::ErrorResponse;

#[derive(Debug, Clone)]
pub enum NetError {
    /// The server answered with a protocol error (`code` is stable, e.g. `locked`, `revoked`).
    Api {
        status: u16,
        code: String,
        message: String,
    },
    /// The server could not be reached or answered with something unintelligible.
    Transport(String),
    /// The server's answer failed cryptographic verification. Treat the server as hostile
    /// or the path as tampered with.
    Verification(String),
}

impl NetError {
    pub fn code(&self) -> Option<&str> {
        match self {
            NetError::Api { code, .. } => Some(code),
            _ => None,
        }
    }

    /// True when retrying cannot help without an administrator acting on the key server.
    pub fn is_policy_denial(&self) -> bool {
        matches!(
            self.code(),
            Some("revoked" | "suspended" | "locked" | "network_denied")
        )
    }
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::Api {
                status,
                code,
                message,
            } => write!(f, "{message} [{code}, HTTP {status}]"),
            NetError::Transport(m) => write!(f, "unreachable: {m}"),
            NetError::Verification(m) => write!(f, "VERIFICATION FAILED: {m}"),
        }
    }
}

impl std::error::Error for NetError {}

#[derive(Clone)]
pub struct Http {
    agent: ureq::Agent,
}

impl Http {
    pub fn new(timeout: Duration) -> Self {
        Http {
            agent: ureq::AgentBuilder::new()
                .timeout_connect(timeout)
                .timeout(timeout * 2)
                .user_agent(concat!("zknbe/", env!("CARGO_PKG_VERSION")))
                .build(),
        }
    }

    fn finish<T: DeserializeOwned>(
        result: Result<ureq::Response, ureq::Error>,
    ) -> Result<T, NetError> {
        match result {
            Ok(resp) => resp
                .into_json::<T>()
                .map_err(|e| NetError::Transport(format!("malformed response: {e}"))),
            Err(ureq::Error::Status(status, resp)) => {
                let text = resp.into_string().unwrap_or_default();
                match serde_json::from_str::<ErrorResponse>(&text) {
                    Ok(e) => Err(NetError::Api {
                        status,
                        code: e.error,
                        message: e.message,
                    }),
                    Err(_) => Err(NetError::Transport(format!("HTTP {status}"))),
                }
            }
            Err(e) => Err(NetError::Transport(e.to_string())),
        }
    }

    pub fn post<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        base: &str,
        path: &str,
        body: &Req,
    ) -> Result<Resp, NetError> {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        Self::finish(self.agent.post(&url).send_json(body))
    }

    pub fn get<Resp: DeserializeOwned>(&self, base: &str, path: &str) -> Result<Resp, NetError> {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        Self::finish(self.agent.get(&url).call())
    }
}
