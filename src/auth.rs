//! OIDC single sign-on for the human-facing surface (`/ui` PWA + `/api` admin
//! API). The S3 gateway keeps its own SigV4 auth — OIDC is a browser flow and
//! does not apply to machine clients.
//!
//! Design, contrasted with a full account system (e.g. hitch's):
//!   * **No user model, no DB.** simplecas has no users table and every
//!     instance is stateless. So there is nothing to provision or link — any
//!     identity that authenticates at a configured provider is admitted
//!     (optionally narrowed by an email allowlist).
//!   * **Stateless sessions.** A successful login sets an HMAC-signed cookie
//!     carrying the identity + expiry. No session table, no server-side
//!     revocation; instances only need the same `session_secret`. Logout
//!     clears the cookie.
//!   * **Stateless flow state.** The per-login CSRF token, nonce and PKCE
//!     verifier ride along in a second short-lived signed cookie across the
//!     redirect to the provider and back, so the callback needs no shared
//!     store either.
//!
//! Provider discovery (incl. the signing JWKS) runs at startup and is refreshed
//! periodically by [`refresh_loop`] so IdP key rotation doesn't break logins on
//! a long-running instance.

use crate::cas::AppState;
use crate::config::OidcConfig;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use hmac::{Hmac, Mac};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

type HmacSha256 = Hmac<Sha256>;

const SESSION_COOKIE: &str = "scas_session";
const FLOW_COOKIE: &str = "scas_oidc_flow";
/// A login ceremony must complete within this window.
const FLOW_TTL_SECS: i64 = 600;
/// How often provider metadata (and its JWKS) is re-discovered.
const REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

/// A configured, discovered provider. Metadata sits behind a lock so the
/// refresh loop can swap in freshly-fetched signing keys without a restart.
pub struct OidcProvider {
    id: String,
    name: String,
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_url: String,
    /// Extra scopes beyond `openid` (which the auth-code flow adds itself).
    scopes: Vec<String>,
    metadata: RwLock<CoreProviderMetadata>,
}

/// All configured providers in declaration order, plus the shared HTTP client.
pub struct OidcRegistry {
    providers: Vec<OidcProvider>,
    by_id: HashMap<String, usize>,
    http_client: openidconnect::reqwest::Client,
}

impl OidcRegistry {
    fn get(&self, id: &str) -> Option<&OidcProvider> {
        self.by_id.get(id).map(|&i| &self.providers[i])
    }
}

/// Perform OIDC discovery for every configured provider, returning `None` when
/// OIDC is disabled. Fails fast on misconfiguration or an unreachable issuer so
/// a broken auth setup never boots silently.
pub async fn build_registry(cfg: &OidcConfig) -> anyhow::Result<Option<Arc<OidcRegistry>>> {
    if !cfg.enabled {
        return Ok(None);
    }
    if cfg.public_url.trim().is_empty() {
        anyhow::bail!(
            "oidc.enabled is set but oidc.public_url is empty (needed to derive redirect URIs)"
        );
    }
    if cfg.session_secret.len() < 16 {
        anyhow::bail!(
            "oidc.session_secret must be set to at least 16 characters when oidc is enabled"
        );
    }
    if cfg.providers.is_empty() {
        anyhow::bail!("oidc.enabled is set but no [[oidc.providers]] are configured");
    }

    let http_client = openidconnect::reqwest::ClientBuilder::new()
        // A relying party must never follow redirects from the token endpoint.
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()?;

    let public = cfg.public_url.trim_end_matches('/').to_string();
    let mut providers = Vec::with_capacity(cfg.providers.len());
    let mut by_id = HashMap::new();

    for pc in &cfg.providers {
        if pc.id.is_empty() || pc.issuer.is_empty() || pc.client_id.is_empty() {
            anyhow::bail!(
                "oidc provider {:?}: id, issuer and client_id are all required",
                pc.id
            );
        }
        if by_id.contains_key(&pc.id) {
            anyhow::bail!("duplicate oidc provider id {:?}", pc.id);
        }
        let metadata =
            CoreProviderMetadata::discover_async(IssuerUrl::new(pc.issuer.clone())?, &http_client)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("oidc discovery for provider {:?} failed: {e}", pc.id)
                })?;

        by_id.insert(pc.id.clone(), providers.len());
        providers.push(OidcProvider {
            id: pc.id.clone(),
            name: pc.name.clone().unwrap_or_else(|| pc.id.clone()),
            issuer: pc.issuer.clone(),
            client_id: pc.client_id.clone(),
            client_secret: pc.client_secret.clone(),
            redirect_url: format!("{public}/auth/oidc/{}/callback", pc.id),
            scopes: effective_scopes(&pc.scopes),
            metadata: RwLock::new(metadata),
        });
    }

    tracing::info!(
        providers = providers.len(),
        "oidc enabled; /ui and /api require sign-in"
    );
    Ok(Some(Arc::new(OidcRegistry {
        providers,
        by_id,
        http_client,
    })))
}

/// `openid` is added by the auth-code flow itself; keep the rest, defaulting to
/// email + profile so the ID token carries an address for the allowlist.
fn effective_scopes(configured: &[String]) -> Vec<String> {
    let base: Vec<String> = if configured.is_empty() {
        ["openid", "email", "profile"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        configured.to_vec()
    };
    base.into_iter().filter(|s| s != "openid").collect()
}

/// Background task: periodically re-discover each provider so rotated IdP
/// signing keys are picked up without a restart. On failure the cached metadata
/// is kept (a transient discovery outage must not lock everyone out).
pub async fn refresh_loop(state: Arc<AppState>) {
    let Some(reg) = state.oidc.clone() else {
        return;
    };
    loop {
        tokio::time::sleep(REFRESH_INTERVAL).await;
        for p in &reg.providers {
            let issuer = match IssuerUrl::new(p.issuer.clone()) {
                Ok(u) => u,
                Err(_) => continue,
            };
            match CoreProviderMetadata::discover_async(issuer, &reg.http_client).await {
                Ok(m) => *p.metadata.write().await = m,
                Err(e) => {
                    tracing::warn!(provider = %p.id, error = %e, "oidc metadata refresh failed; keeping cached keys")
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Signed cookies
// ---------------------------------------------------------------------------

/// `base64url(payload).base64url(HMAC-SHA256(payload))`.
fn sign(secret: &str, payload: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload);
    let tag = mac.finalize().into_bytes();
    format!("{}.{}", b64.encode(payload), b64.encode(tag))
}

/// Verify the tag (constant time) and return the payload, or `None` if the
/// token is malformed or the signature doesn't match.
fn unsign(secret: &str, token: &str) -> Option<Vec<u8>> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (payload_b64, tag_b64) = token.split_once('.')?;
    let payload = b64.decode(payload_b64).ok()?;
    let tag = b64.decode(tag_b64).ok()?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(&payload);
    mac.verify_slice(&tag).ok()?;
    Some(payload)
}

fn secure_cookies(cfg: &OidcConfig) -> bool {
    cfg.public_url.starts_with("https")
}

fn set_cookie(name: &str, value: &str, max_age_secs: i64, secure: bool) -> String {
    let mut c = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}");
    if secure {
        c.push_str("; Secure");
    }
    c
}

fn clear_cookie(name: &str, secure: bool) -> String {
    set_cookie(name, "", 0, secure)
}

fn read_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

fn redirect_with_cookies(location: &str, cookies: &[String]) -> Response {
    let mut resp = Redirect::to(location).into_response();
    let headers = resp.headers_mut();
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            headers.append(header::SET_COOKIE, v);
        }
    }
    resp
}

// ---------------------------------------------------------------------------
// Session + flow state
// ---------------------------------------------------------------------------

/// The identity carried in the session cookie.
#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    pub provider: String,
    /// Unix expiry.
    pub exp: i64,
}

/// Per-login state that must survive the round trip to the provider.
#[derive(Debug, Serialize, Deserialize)]
struct FlowState {
    provider: String,
    csrf: String,
    nonce: String,
    pkce_verifier: String,
    redirect_after: String,
    exp: i64,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Read and validate the session cookie, if present and unexpired.
fn current_session(headers: &HeaderMap, cfg: &OidcConfig) -> Option<Session> {
    let raw = read_cookie(headers, SESSION_COOKIE)?;
    let bytes = unsign(&cfg.session_secret, raw)?;
    let session: Session = serde_json::from_slice(&bytes).ok()?;
    (session.exp > now()).then_some(session)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |r, (x, y)| r | (x ^ y)) == 0
}

/// Only permit same-site absolute paths, to prevent open redirects.
fn sanitize_redirect(raw: Option<String>) -> String {
    match raw {
        Some(r) if r.starts_with('/') && !r.starts_with("//") => r,
        _ => "/ui/".to_string(),
    }
}

/// Decide whether an authenticated identity is admitted. Empty allowlists =
/// admit anyone. A configured allowlist trusts the email, so an unverified (or
/// absent) email is rejected.
fn admitted(cfg: &OidcConfig, email: Option<&str>, verified: Option<bool>) -> bool {
    if cfg.allowed_domains.is_empty() && cfg.allowed_emails.is_empty() {
        return true;
    }
    let Some(email) = email else { return false };
    if verified != Some(true) {
        return false;
    }
    if cfg
        .allowed_emails
        .iter()
        .any(|e| e.eq_ignore_ascii_case(email))
    {
        return true;
    }
    match email.rsplit_once('@') {
        Some((_, domain)) => cfg
            .allowed_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(domain)),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Guard middleware
// ---------------------------------------------------------------------------

/// Applied to the `/ui` and `/api` routers when OIDC is enabled. Unauthenticated
/// API calls get 401 JSON; unauthenticated page loads redirect to the login
/// page, preserving the intended destination.
pub async fn guard(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let cfg = &state.config.oidc;
    if current_session(request.headers(), cfg).is_some() {
        return next.run(request).await;
    }
    if request.uri().path().starts_with("/api") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "code": "Unauthorized", "message": "sign-in required" })),
        )
            .into_response();
    }
    let dest = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/ui/");
    let q = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("redirect", dest)
        .finish();
    Redirect::to(&format!("/auth/login?{q}")).into_response()
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/login", get(login_page))
        .route("/auth/logout", get(logout))
        .route("/auth/me", get(me))
        .route("/auth/oidc/{provider}/start", get(start))
        .route("/auth/oidc/{provider}/callback", get(callback))
}

#[derive(Deserialize)]
struct RedirectQuery {
    #[serde(default)]
    redirect: Option<String>,
    #[serde(default)]
    oidc_error: Option<String>,
}

async fn login_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<RedirectQuery>,
) -> Response {
    let Some(reg) = &state.oidc else {
        return (StatusCode::NOT_FOUND, "sign-in is not enabled").into_response();
    };
    let cfg = &state.config.oidc;
    let dest = sanitize_redirect(q.redirect);
    // Already signed in — nothing to do.
    if current_session(&headers, cfg).is_some() {
        return Redirect::to(&dest).into_response();
    }
    let redirect_enc = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("redirect", &dest)
        .finish();

    let mut buttons = String::new();
    for p in &reg.providers {
        buttons.push_str(&format!(
            "<a class=\"btn\" href=\"/auth/oidc/{id}/start?{q}\">Continue with {name}</a>",
            id = html_escape(&p.id),
            q = redirect_enc,
            name = html_escape(&p.name),
        ));
    }
    let error_html = match q.oidc_error {
        Some(code) if !code.is_empty() => {
            format!(
                "<p class=\"err\">Sign-in failed: {}</p>",
                html_escape(&code)
            )
        }
        _ => String::new(),
    };

    Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>Sign in · simplecas</title>\
<style>body{{font:16px system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#0b0d10;color:#e7e9ea}}\
.card{{display:flex;flex-direction:column;gap:12px;padding:32px;min-width:280px}}\
h1{{font-size:20px;margin:0 0 8px;text-align:center}}\
.btn{{display:block;padding:12px 16px;border-radius:8px;background:#1f6feb;color:#fff;text-decoration:none;text-align:center;font-weight:600}}\
.btn:hover{{background:#388bfd}}.err{{color:#f85149;text-align:center;margin:0}}</style></head>\
<body><div class=\"card\"><h1>simplecas</h1>{error_html}{buttons}</div></body></html>"
    ))
    .into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn logout(State(state): State<Arc<AppState>>) -> Response {
    let secure = secure_cookies(&state.config.oidc);
    redirect_with_cookies("/auth/login", &[clear_cookie(SESSION_COOKIE, secure)])
}

async fn me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match current_session(&headers, &state.config.oidc) {
        Some(s) => Json(json!({
            "sub": s.sub,
            "email": s.email,
            "name": s.name,
            "provider": s.provider,
        }))
        .into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "code": "Unauthorized", "message": "not signed in" })),
        )
            .into_response(),
    }
}

/// Begin a login: stash flow state in a signed cookie and redirect to the
/// provider's authorization endpoint.
async fn start(
    State(state): State<Arc<AppState>>,
    Path(provider_id): Path<String>,
    Query(q): Query<RedirectQuery>,
) -> Response {
    let Some(reg) = &state.oidc else {
        return (StatusCode::NOT_FOUND, "sign-in is not enabled").into_response();
    };
    let cfg = &state.config.oidc;
    let Some(p) = reg.get(&provider_id) else {
        return (StatusCode::NOT_FOUND, "unknown identity provider").into_response();
    };

    let metadata = p.metadata.read().await.clone();
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(p.client_id.clone()),
        p.client_secret.clone().map(ClientSecret::new),
    )
    .set_redirect_uri(match RedirectUrl::new(p.redirect_url.clone()) {
        Ok(u) => u,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "bad redirect uri").into_response(),
    });

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut req = client.authorize_url(
        CoreAuthenticationFlow::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    );
    for scope in &p.scopes {
        req = req.add_scope(Scope::new(scope.clone()));
    }
    let (auth_url, csrf, nonce) = req.set_pkce_challenge(challenge).url();

    let flow = FlowState {
        provider: provider_id,
        csrf: csrf.secret().clone(),
        nonce: nonce.secret().clone(),
        pkce_verifier: verifier.secret().clone(),
        redirect_after: sanitize_redirect(q.redirect),
        exp: now() + FLOW_TTL_SECS,
    };
    let cookie = set_cookie(
        FLOW_COOKIE,
        &sign(
            &cfg.session_secret,
            &serde_json::to_vec(&flow).expect("serialize flow state"),
        ),
        FLOW_TTL_SECS,
        secure_cookies(cfg),
    );
    redirect_with_cookies(auth_url.as_str(), &[cookie])
}

#[derive(Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Handle the provider callback: validate flow state + CSRF, exchange the code,
/// verify the ID token (signature + nonce), apply the allowlist, and open a
/// session.
async fn callback(
    State(state): State<Arc<AppState>>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let Some(reg) = &state.oidc else {
        return (StatusCode::NOT_FOUND, "sign-in is not enabled").into_response();
    };
    let cfg = &state.config.oidc;

    if let Some(err) = q.error.filter(|e| !e.is_empty()) {
        return login_error(cfg, &err);
    }
    let Some(p) = reg.get(&provider_id) else {
        return (StatusCode::NOT_FOUND, "unknown identity provider").into_response();
    };

    // Recover and validate flow state from the signed cookie.
    let Some(flow) = read_cookie(&headers, FLOW_COOKIE)
        .and_then(|raw| unsign(&cfg.session_secret, raw))
        .and_then(|b| serde_json::from_slice::<FlowState>(&b).ok())
    else {
        return login_error(cfg, "state_missing");
    };
    if flow.exp < now() || flow.provider != provider_id {
        return login_error(cfg, "state_expired");
    }
    let (Some(code), Some(state_param)) = (q.code, q.state) else {
        return login_error(cfg, "missing_code");
    };
    if !ct_eq(state_param.as_bytes(), flow.csrf.as_bytes()) {
        return login_error(cfg, "state_mismatch");
    }

    let session = match complete_login(reg, cfg, p, &provider_id, code, &flow).await {
        Ok(s) => s,
        Err(code) => return login_error(cfg, code),
    };

    let secure = secure_cookies(cfg);
    let session_cookie = set_cookie(
        SESSION_COOKIE,
        &sign(
            &cfg.session_secret,
            &serde_json::to_vec(&session).expect("serialize session"),
        ),
        cfg.session_ttl_secs as i64,
        secure,
    );
    redirect_with_cookies(
        &flow.redirect_after,
        &[session_cookie, clear_cookie(FLOW_COOKIE, secure)],
    )
}

/// The fallible half of the callback: token exchange, ID-token verification and
/// the allowlist check. Errors are short machine codes surfaced on the login
/// page.
async fn complete_login(
    reg: &OidcRegistry,
    cfg: &OidcConfig,
    p: &OidcProvider,
    provider_id: &str,
    code: String,
    flow: &FlowState,
) -> Result<Session, &'static str> {
    let metadata = p.metadata.read().await.clone();
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(p.client_id.clone()),
        p.client_secret.clone().map(ClientSecret::new),
    )
    .set_redirect_uri(RedirectUrl::new(p.redirect_url.clone()).map_err(|_| "server_error")?);

    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|_| "server_error")?
        .set_pkce_verifier(PkceCodeVerifier::new(flow.pkce_verifier.clone()))
        .request_async(&reg.http_client)
        .await
        .map_err(|_| "exchange_failed")?;

    let id_token = token_response.id_token().ok_or("no_id_token")?;
    let claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(flow.nonce.clone()))
        .map_err(|_| "token_invalid")?;

    let email = claims.email().map(|e| e.as_str().to_string());
    let verified = claims.email_verified();
    if !admitted(cfg, email.as_deref(), verified) {
        return Err("not_allowed");
    }

    let name = claims
        .name()
        .and_then(|n| n.get(None))
        .map(|n| n.as_str().to_string());

    Ok(Session {
        sub: claims.subject().as_str().to_string(),
        email,
        name,
        provider: provider_id.to_string(),
        exp: now() + cfg.session_ttl_secs as i64,
    })
}

fn login_error(cfg: &OidcConfig, code: &str) -> Response {
    let secure = secure_cookies(cfg);
    let q = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("oidc_error", code)
        .finish();
    // Also clear any stale flow cookie so a retry starts clean.
    redirect_with_cookies(
        &format!("/auth/login?{q}"),
        &[clear_cookie(FLOW_COOKIE, secure)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(domains: &[&str], emails: &[&str]) -> OidcConfig {
        OidcConfig {
            allowed_domains: domains.iter().map(|s| s.to_string()).collect(),
            allowed_emails: emails.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_allowlist_admits_anyone() {
        assert!(admitted(&cfg(&[], &[]), None, None));
        assert!(admitted(&cfg(&[], &[]), Some("x@any.example"), Some(false)));
    }

    #[test]
    fn allowlist_requires_verified_matching_email() {
        let c = cfg(&["lunit.io"], &["ceo@other.example"]);
        assert!(admitted(&c, Some("dev@lunit.io"), Some(true)));
        assert!(admitted(&c, Some("DEV@LUNIT.IO"), Some(true)));
        assert!(admitted(&c, Some("ceo@other.example"), Some(true)));
        // wrong domain
        assert!(!admitted(&c, Some("dev@evil.example"), Some(true)));
        // right domain but unverified
        assert!(!admitted(&c, Some("dev@lunit.io"), Some(false)));
        assert!(!admitted(&c, Some("dev@lunit.io"), None));
        // no email at all
        assert!(!admitted(&c, None, Some(true)));
    }

    #[test]
    fn sign_roundtrip_and_tamper() {
        let secret = "0123456789abcdef0123456789abcdef";
        let token = sign(secret, b"hello world");
        assert_eq!(unsign(secret, &token).as_deref(), Some(&b"hello world"[..]));
        assert!(unsign("different-secret-value!!", &token).is_none());
        // tamper with the payload
        let (_, tag) = token.split_once('.').unwrap();
        let forged = format!(
            "{}.{tag}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"goodbye")
        );
        assert!(unsign(secret, &forged).is_none());
    }

    #[test]
    fn sanitize_redirect_blocks_offsite() {
        assert_eq!(sanitize_redirect(Some("/ui/x".into())), "/ui/x");
        assert_eq!(sanitize_redirect(Some("//evil.example".into())), "/ui/");
        assert_eq!(
            sanitize_redirect(Some("https://evil.example".into())),
            "/ui/"
        );
        assert_eq!(sanitize_redirect(None), "/ui/");
    }
}
