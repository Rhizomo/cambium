//! Nexus Repository 3 REST API client (`/service/rest/v1/security/*`).
//!
//! Behavior below was verified live against a disposable local
//! `sonatype/nexus3:latest` container (never against any private/production
//! Nexus instance) — see `docs/sync-semantics.md` section 1 for the full
//! writeup. The load-bearing facts baked into this client:
//!
//! - `POST /v1/security/users` creates a user **and** assigns its initial
//!   roles in one call (`ApiCreateUser.roles`).
//! - There is no per-role assign/revoke endpoint. The only way to change an
//!   existing user's roles is `PUT /v1/security/users/{userId}` with a full
//!   `ApiUser` body — `roles` is a whole-array replace, not a patch. Cambium
//!   must therefore always compute the complete desired role set before
//!   calling this (see `src/sync.rs`).
//! - `PUT` requires `source` in the body even though it can't be changed;
//!   omitting it fails with `400 {"id":"PARAMETER source", ...}`.
//! - There is no `GET /users/{userId}` single-resource endpoint — only
//!   `GET /users?userId=<substring>`, which does a fuzzy/substring match, so
//!   callers must filter the result for an exact `userId` match themselves.
//! - Creating a `userId` that already exists does **not** return a clean
//!   409. It throws a raw exception surfaced as a `500` with a plain-text
//!   (not JSON) body containing `DuplicateUserException`. This client
//!   detects that string and reports it as
//!   [`CambiumError::NexusUserAlreadyExists`] so callers can fall back to an
//!   update instead of treating it as a generic server failure.

use serde::{Deserialize, Serialize};

use crate::error::{CambiumError, CambiumResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NexusUser {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "firstName")]
    pub first_name: String,
    #[serde(rename = "lastName")]
    pub last_name: String,
    #[serde(rename = "emailAddress")]
    pub email_address: String,
    pub source: String,
    pub status: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(rename = "externalRoles", default)]
    pub external_roles: Vec<String>,
}

pub struct NewNexusUser {
    pub user_id: String,
    pub first_name: String,
    pub last_name: String,
    pub email_address: String,
    pub password: String,
    pub roles: Vec<String>,
}

pub struct NexusClient {
    http: reqwest::Client,
    base_url: String,
    username: String,
    password: String,
}

impl NexusClient {
    pub fn new(base_url: impl Into<String>, username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            http: crate::http::api_client(),
            base_url: base_url.into(),
            username: username.into(),
            password: password.into(),
        }
    }

    fn security_url(&self, path: &str) -> String {
        format!("{}/service/rest/v1/security{path}", self.base_url)
    }

    /// `GET /v1/security/users?userId=<term>`, filtered client-side for an
    /// exact match since Nexus's `userId` query param is a fuzzy search, not
    /// an exact filter.
    pub async fn get_user(&self, user_id: &str) -> CambiumResult<Option<NexusUser>> {
        let url = format!(
            "{}?userId={}",
            self.security_url("/users"),
            urlencoding::encode(user_id)
        );
        let resp = self
            .http
            .get(&url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CambiumError::NexusUnexpected { status, body });
        }

        let users: Vec<NexusUser> = resp.json().await?;
        Ok(users.into_iter().find(|u| u.user_id == user_id))
    }

    /// `POST /v1/security/users`. Returns
    /// [`CambiumError::NexusUserAlreadyExists`] if the user already exists,
    /// distinguished from other 5xx failures by inspecting the (plain-text)
    /// error body for Nexus's `DuplicateUserException` marker.
    pub async fn create_user(&self, new_user: NewNexusUser) -> CambiumResult<NexusUser> {
        let body = serde_json::json!({
            "userId": new_user.user_id,
            "firstName": new_user.first_name,
            "lastName": new_user.last_name,
            "emailAddress": new_user.email_address,
            "password": new_user.password,
            "status": "active",
            "roles": new_user.roles,
        });

        let url = self.security_url("/users");
        let resp = self
            .http
            .post(&url)
            .basic_auth(&self.username, Some(&self.password))
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            return Ok(resp.json().await?);
        }

        let text = resp.text().await.unwrap_or_default();

        if status.as_u16() == 500 && text.contains("DuplicateUserException") {
            return Err(CambiumError::NexusUserAlreadyExists(new_user.user_id));
        }

        if status.as_u16() == 400 {
            if let Ok(errs) = serde_json::from_str::<Vec<NexusValidationEntry>>(&text) {
                if let Some(first) = errs.into_iter().next() {
                    return Err(CambiumError::NexusValidation {
                        field: Some(first.id),
                        message: first.message,
                    });
                }
            }
        }

        Err(CambiumError::NexusUnexpected {
            status: status.as_u16(),
            body: text,
        })
    }

    /// `PUT /v1/security/users/{userId}` with a full `ApiUser` body — the
    /// only way Nexus exposes to change a user's role set. `desired_roles`
    /// must already be the *complete* set to end up with (see
    /// `docs/sync-semantics.md` for how `src/sync.rs` computes that without
    /// clobbering manually-assigned roles).
    pub async fn set_user_roles(
        &self,
        current: &NexusUser,
        desired_roles: Vec<String>,
    ) -> CambiumResult<()> {
        let body = serde_json::json!({
            "userId": current.user_id,
            "firstName": current.first_name,
            "lastName": current.last_name,
            "emailAddress": current.email_address,
            "source": current.source,
            "status": current.status,
            "roles": desired_roles,
        });

        let url = format!("{}/{}", self.security_url("/users"), current.user_id);
        let resp = self
            .http
            .put(&url)
            .basic_auth(&self.username, Some(&self.password))
            .json(&body)
            .send()
            .await?;

        if resp.status().is_success() {
            return Ok(());
        }

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        Err(CambiumError::NexusUnexpected { status, body })
    }
}

#[derive(Deserialize)]
struct NexusValidationEntry {
    id: String,
    message: String,
}
