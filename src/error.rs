use thiserror::Error;

#[derive(Debug, Error)]
pub enum CambiumError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Keycloak API returned {status}: {body}")]
    KeycloakUnexpected { status: u16, body: String },

    #[error("Nexus API returned {status}: {body}")]
    NexusUnexpected { status: u16, body: String },

    #[error("Nexus rejected the request as invalid ({field:?}): {message}")]
    NexusValidation { field: Option<String>, message: String },

    #[error("resource not found")]
    NotFound,

    #[error("Nexus user {0:?} already exists")]
    NexusUserAlreadyExists(String),

    #[error("failed to (de)serialize JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("manifest I/O error at {path}: {source}")]
    ManifestIo {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid {var} {value:?}: {reason}")]
    InvalidUpstreamUrl {
        var: String,
        value: String,
        reason: String,
    },

    #[error("invalid ROLE_MAP entry {0:?} (expected \"keycloak-group:nexus-role\")")]
    InvalidRoleMapEntry(String),
}

pub type CambiumResult<T> = Result<T, CambiumError>;
