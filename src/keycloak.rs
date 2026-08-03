//! Keycloak Admin REST API client.
//!
//! Style/patterns follow `grafter`'s `src/provider/keycloak.rs` (same
//! author/org, same license) — token caching, thin get/post helpers. This is
//! a clean-room rewrite scoped to exactly what Cambium needs: groups, group
//! membership, and effective realm role mappings. No Nexus-specific or
//! proprietary code is involved here at all; this file only talks to
//! Keycloak's public Admin REST API.
//!
//! See `docs/sync-semantics.md` section 1 for how the "effective role
//! mappings, direct and group-inherited" question was resolved: Keycloak's
//! own `.../role-mappings/realm/composite` endpoint expands composite role
//! hierarchies but does **not** walk group membership, so Cambium computes
//! the union itself:
//!
//! ```text
//! effective_roles(user) = composite(user.direct_roles)
//!                        ∪ ⋃_{g in user.groups} composite(g.direct_roles)
//! ```

use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::error::{CambiumError, CambiumResult};

#[derive(Debug, Clone, Deserialize)]
pub struct KcGroup {
    pub id: String,
    // Not read by Cambium's own logic today, but kept because it's part of
    // Keycloak's actual response shape and useful when debugging/logging.
    #[allow(dead_code)]
    pub name: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KcUser {
    pub id: String,
    pub username: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub email: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct KcRole {
    #[allow(dead_code)]
    id: String,
    name: String,
}

#[derive(Default)]
struct TokenCache {
    token: Option<String>,
    expires_at: Option<Instant>,
}

pub struct KeycloakClient {
    http: reqwest::Client,
    admin_url: String,
    admin_realm: String,
    client_id: String,
    client_secret: String,
    token_cache: Arc<RwLock<TokenCache>>,
}

impl KeycloakClient {
    pub fn new(
        admin_url: impl Into<String>,
        admin_realm: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            admin_url: admin_url.into(),
            admin_realm: admin_realm.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            token_cache: Arc::new(RwLock::new(TokenCache::default())),
        }
    }

    fn realm_url(&self, realm: &str) -> String {
        format!("{}/admin/realms/{realm}", self.admin_url)
    }

    async fn token(&self) -> CambiumResult<String> {
        {
            let cache = self.token_cache.read().await;
            if let (Some(t), Some(exp)) = (&cache.token, cache.expires_at) {
                if Instant::now() < exp {
                    return Ok(t.clone());
                }
            }
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: u64,
        }

        let url = format!(
            "{}/realms/{}/protocol/openid-connect/token",
            self.admin_url, self.admin_realm
        );

        let resp = self
            .http
            .post(&url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CambiumError::KeycloakUnexpected { status, body });
        }

        let tr: TokenResponse = resp.json().await?;
        let expires_at = Instant::now() + Duration::from_secs(tr.expires_in.saturating_sub(30));

        let mut cache = self.token_cache.write().await;
        cache.token = Some(tr.access_token.clone());
        cache.expires_at = Some(expires_at);
        Ok(tr.access_token)
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, url: &str) -> CambiumResult<T> {
        let token = self.token().await?;
        let resp = self.http.get(url).bearer_auth(&token).send().await?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(CambiumError::NotFound);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CambiumError::KeycloakUnexpected { status, body });
        }
        Ok(resp.json().await?)
    }

    /// `GET /admin/realms/{realm}/groups` — all top-level groups in the realm.
    pub async fn list_groups(&self, realm: &str) -> CambiumResult<Vec<KcGroup>> {
        let url = format!("{}/groups?briefRepresentation=true", self.realm_url(realm));
        self.get(&url).await
    }

    /// `GET /admin/realms/{realm}/groups/{id}/members` — a group's direct members.
    pub async fn group_members(&self, realm: &str, group_id: &str) -> CambiumResult<Vec<KcUser>> {
        let url = format!(
            "{}/groups/{}/members?max=1000",
            self.realm_url(realm),
            group_id
        );
        self.get(&url).await
    }

    /// `GET /admin/realms/{realm}/users/{id}/groups` — the groups a user directly belongs to.
    pub async fn user_groups(&self, realm: &str, user_id: &str) -> CambiumResult<Vec<KcGroup>> {
        let url = format!("{}/users/{}/groups", self.realm_url(realm), user_id);
        self.get(&url).await
    }

    /// `GET /admin/realms/{realm}/users/{id}/role-mappings/realm/composite` —
    /// the user's own direct realm roles, composite-expanded. Does **not**
    /// include roles inherited via group membership (see module docs).
    pub async fn user_composite_realm_roles(
        &self,
        realm: &str,
        user_id: &str,
    ) -> CambiumResult<HashSet<String>> {
        let url = format!(
            "{}/users/{}/role-mappings/realm/composite",
            self.realm_url(realm),
            user_id
        );
        let roles: Vec<KcRole> = self.get(&url).await?;
        Ok(roles.into_iter().map(|r| r.name).collect())
    }

    /// `GET /admin/realms/{realm}/groups/{id}/role-mappings/realm/composite` —
    /// a group's own direct realm roles, composite-expanded.
    pub async fn group_composite_realm_roles(
        &self,
        realm: &str,
        group_id: &str,
    ) -> CambiumResult<HashSet<String>> {
        let url = format!(
            "{}/groups/{}/role-mappings/realm/composite",
            self.realm_url(realm),
            group_id
        );
        let roles: Vec<KcRole> = self.get(&url).await?;
        Ok(roles.into_iter().map(|r| r.name).collect())
    }

    /// The full "effective realm roles, direct or group-inherited" answer
    /// for one user: union of the user's own composite-expanded roles and
    /// the composite-expanded roles of every group they belong to.
    pub async fn effective_realm_roles(
        &self,
        realm: &str,
        user_id: &str,
    ) -> CambiumResult<HashSet<String>> {
        let mut roles = self.user_composite_realm_roles(realm, user_id).await?;

        let groups = self.user_groups(realm, user_id).await?;
        for group in groups {
            let group_roles = self.group_composite_realm_roles(realm, &group.id).await?;
            roles.extend(group_roles);
        }

        Ok(roles)
    }
}
