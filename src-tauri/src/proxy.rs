//! Codex Switcher - 本地 HTTP/WebSocket 代理服务器
//!
//! 透明代理：拦截 Codex CLI/App 请求，动态注入当前账号 Token 并转发。
//! HTTP: Header 转发逻辑与官方 responses-api-proxy 一致
//! WebSocket: 双向桥接，支持 Codex App 的 WebSocket 通信
//!
//! 功能：SSE 流式转发 | WebSocket 透传 | 429 自动切号 | 封号检测 | 评分选号

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use tauri::Emitter;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite;
use tungstenite::client::IntoClientRequest;

use crate::account::{AccountKind, AccountStore};
use crate::session_affinity::SessionAffinity;
use crate::session_routes::SessionRoutesStore;
use crate::sse_watchdog::{wrap_with_sse_watchdog, SseStreamDiagnostic};
use crate::switch_log::{SwitchLogger, SwitchReason};
use crate::token_tracker::TokenTracker;

const CHATGPT_ACCOUNT_ID_HEADER: &str = "chatgpt-account-id";

/// 待注入的切号通知消息
static PENDING_INJECT_MSG: std::sync::LazyLock<Mutex<Option<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

/// client 模式下，per-account 的 token 短期缓存（避免每次请求都 round-trip Server）
struct RemoteTokenCacheEntry {
    token: String,
    is_chatgpt: bool,
    at: std::time::Instant,
}

const REMOTE_TOKEN_CACHE_TTL_SECS: u64 = 30;

static REMOTE_TOKEN_CACHE: std::sync::LazyLock<
    Mutex<std::collections::HashMap<String, RemoteTokenCacheEntry>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

#[derive(Clone)]
struct RemoteAntigravityTokenCacheEntry {
    access_token: String,
    project_id: String,
    expires_at: chrono::DateTime<Utc>,
}

static REMOTE_ANTIGRAVITY_TOKEN_CACHE: std::sync::LazyLock<
    Mutex<std::collections::HashMap<String, RemoteAntigravityTokenCacheEntry>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

fn remote_antigravity_token_cache_get(id: &str) -> Option<RemoteAntigravityTokenCacheEntry> {
    let cache = REMOTE_ANTIGRAVITY_TOKEN_CACHE.lock().ok()?;
    let entry = cache.get(id)?;
    (entry.expires_at > Utc::now() + chrono::Duration::minutes(5)).then(|| entry.clone())
}

fn remote_antigravity_token_cache_put(id: &str, entry: RemoteAntigravityTokenCacheEntry) {
    if let Ok(mut cache) = REMOTE_ANTIGRAVITY_TOKEN_CACHE.lock() {
        cache.insert(id.to_string(), entry);
    }
}

fn remote_antigravity_token_cache_remove(id: &str) {
    if let Ok(mut cache) = REMOTE_ANTIGRAVITY_TOKEN_CACHE.lock() {
        cache.remove(id);
    }
}

fn remote_token_cache_get(id: &str) -> Option<(String, bool)> {
    let g = REMOTE_TOKEN_CACHE.lock().ok()?;
    let e = g.get(id)?;
    if e.at.elapsed() < std::time::Duration::from_secs(REMOTE_TOKEN_CACHE_TTL_SECS) {
        Some((e.token.clone(), e.is_chatgpt))
    } else {
        None
    }
}

fn remote_token_cache_put(id: &str, token: &str, is_chatgpt: bool) {
    if let Ok(mut g) = REMOTE_TOKEN_CACHE.lock() {
        g.insert(
            id.to_string(),
            RemoteTokenCacheEntry {
                token: token.to_string(),
                is_chatgpt,
                at: std::time::Instant::now(),
            },
        );
    }
}

/// 401 静默刷新的统一返回。
enum SilentRefreshOutcome {
    /// 拿到新 access_token，调用方应用它重试上游
    Refreshed(String),
    /// auth0 拒绝（RT 已轮换 / 用户登出 / 切号到别处）→ 调用方应该切号
    LoggedOut,
    /// 其他错误（网络抖动等），调用方按原路径返回 401
    OtherError(String),
    /// 当前账号根本没 refresh_token，没法刷
    NoRefreshToken,
}

/// 按 remote_mode 决定刷新路径：
/// - **client / solo**：先尝试问 Server 拿 fresh token（Server 是 RT 轮换的权威），
///   Server 不可达再降级本地 oauth refresh
/// - **off / server**：直接本地 oauth refresh
///
/// 成功后：apply 到 store + 写盘 + 写 ~/.codex/auth.json，把 RT 竞态窗口压到几毫秒。
async fn silent_refresh_current(state: &ProxyState) -> SilentRefreshOutcome {
    let (current_id, remote_mode, primary, fallback, secret) = {
        let store = match state.store.lock() {
            Ok(s) => s,
            Err(_) => return SilentRefreshOutcome::OtherError("store lock 失败".into()),
        };
        let Some(cid) = store.current.clone() else {
            return SilentRefreshOutcome::NoRefreshToken;
        };
        (
            cid,
            store.settings.remote_mode.clone(),
            store.settings.remote_server_url.clone(),
            store.settings.remote_server_url_fallback.clone(),
            store.settings.remote_shared_secret.clone(),
        )
    };

    // 1) 优先走 Server（client/solo 模式）
    if matches!(remote_mode.as_str(), "client" | "solo") && !secret.is_empty() {
        match crate::remote_client::resolve_base_url(&primary, &fallback).await {
            Ok(base) => {
                // 401 不能只 GET 旧 token：Server 可能还没把刚轮换的 token
                // 写回到它的缓存。本机必须走 Server 的单刷新者端点，由 Server
                // 在账号锁内重新读取/轮换 RT，并把最新 auth_json 返回。
                match crate::remote_client::refresh_token_now(&base, &secret, &current_id).await {
                    Ok(t) => {
                        // 把 Server 的 auth_json 应用到本机 store + 写盘 auth.json
                        let token_str = AccountStore::extract_access_token(&t.auth_json);
                        if let Ok(mut store) = state.store.lock() {
                            store.sync_account_from_auth_json(&current_id, t.auth_json.clone());
                            let _ = store.save();
                        }
                        // 走 anchor-guarded 路径，anchor 设置时跳过非 anchor 账号的写盘
                        write_codex_auth_respecting_anchor(state, &current_id, &t.auth_json);
                        invalidate_remote_token_cache();
                        if let Some(tok) = token_str {
                            println!("[Proxy] 通过 Server 刷新成功（{}），重试请求", remote_mode);
                            return SilentRefreshOutcome::Refreshed(tok);
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[Proxy] Server fetch_token 失败 ({})：{}，降级本地 refresh",
                            remote_mode, e
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "[Proxy] Server 不可达 ({})：{}，降级本地 refresh",
                    remote_mode, e
                );
            }
        }
    }

    // 2) 本地 oauth refresh（**仅** off/server 模式；client/solo 走不到这里）
    //
    // 协议：client/solo 把 rt 权威完全交给 Server。哪怕 Server 抖了一下也不能本机偷偷
    // rotate —— 一旦 rotate，Server 那边的 rt 会立刻被 OpenAI 标 reused 而死号。
    // 让 codex 收个 401 走自己的重试链路，比赌"这一次本机刷成功就好"安全得多。
    if matches!(remote_mode.as_str(), "client" | "solo") {
        return SilentRefreshOutcome::OtherError(
            "client/solo 模式禁止本机 rt 刷新；Server 不可达，跳过本机降级".into(),
        );
    }

    match crate::oauth::refresh_access_token_locked_fresh(&state.store, &current_id).await {
        Ok(new_tokens) => {
            // apply 到 store
            let updated_auth = if let Ok(mut store) = state.store.lock() {
                if let Some(acc) = store.accounts.get_mut(&current_id) {
                    AccountStore::apply_refreshed_tokens(
                        acc,
                        new_tokens.access_token.clone(),
                        new_tokens.refresh_token.clone(),
                        new_tokens.id_token.clone(),
                        new_tokens.expires_in,
                    );
                    let auth = acc.auth_json.clone();
                    let _ = store.save();
                    Some(auth)
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(auth) = updated_auth {
                // anchor 设置时跳过非 anchor 账号的写盘
                write_codex_auth_respecting_anchor(state, &current_id, &auth);
            }
            SilentRefreshOutcome::Refreshed(new_tokens.access_token)
        }
        Err(e) => {
            let lower = e.to_lowercase();
            // 「session 结束 / rt 被作废」= 刷新也救不回，必须重新登录 → 当 LoggedOut(需重登)。
            // 注意 refresh_token_reused 不在此列：那是瞬时轮换冲突，归 OtherError 自愈。
            if lower.contains("logged out")
                || lower.contains("invalid_grant")
                || lower.contains("signed in to another account")
                || lower.contains("refresh_token_invalidated")
                || lower.contains("refresh_token_expired")
                || lower.contains("session has ended")
                || lower.contains("session_expired")
                || lower.contains("please log in again")
                || lower.contains("please sign in again")
            {
                SilentRefreshOutcome::LoggedOut
            } else {
                SilentRefreshOutcome::OtherError(e)
            }
        }
    }
}

/// 切号或账号变化时手动失效（被 perform_switch 调用）
pub fn invalidate_remote_token_cache() {
    if let Ok(mut g) = REMOTE_TOKEN_CACHE.lock() {
        g.clear();
    }
}

/// ChatGPT OAuth 登录用的上游（免费/Plus/Team 账号）
const CHATGPT_HOST: &str = "chatgpt.com";
const CHATGPT_ORIGIN: &str = "https://chatgpt.com/backend-api/codex";

/// API key 用的上游
const API_HOST: &str = "api.openai.com";
const API_ORIGIN: &str = "https://api.openai.com";
const MAX_429_RETRIES: usize = 5;

/// 统一的响应 Body 类型：支持 Full（错误/小响应）和 Stream（SSE 流式）。
/// 用 UnsyncBoxBody 而非 BoxBody —— hyper 的 service 单 task 处理一个连接，不要求 Sync；
/// reqwest 的 bytes_stream 也不保证 Sync，强求 Sync 会触发 trait bound 错误。
type ProxyBody = UnsyncBoxBody<Bytes, String>;

/// 代理运行指标（与 AppState 共享）
pub struct ProxyStats {
    pub total_requests: AtomicU64,
    pub auto_switches: AtomicU64,
}

impl Default for ProxyStats {
    fn default() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            auto_switches: AtomicU64::new(0),
        }
    }
}

/// 代理运行时共享状态
struct ProxyState {
    store: Arc<Mutex<AccountStore>>,
    client: Client,
    /// Native Antigravity keeps one HTTP/1.1 connection pool per Google identity.
    antigravity_clients: Mutex<std::collections::HashMap<String, Client>>,
    app_handle: tauri::AppHandle,
    switching: AtomicBool,
    stats: Arc<ProxyStats>,
    tracker: Arc<TokenTracker>,
    /// 切号时通知 WebSocket 断开
    ws_disconnect: Arc<tokio::sync::Notify>,
    switch_logger: Arc<SwitchLogger>,
    session_affinity: Arc<SessionAffinity>,
    /// 用户级硬路由：session_id → account 强绑定
    session_routes: Arc<Mutex<SessionRoutesStore>>,
    /// 429 冷却：account_id → 冷却到期的 epoch 秒。撞 429 的号在此之前不再被选中，
    /// 避免「5min 额度刷新把 cached 5h 重置回 99% → 立刻又被选中 → 又 429」的来回切号风暴
    /// （cached 5h% 不反映某些模型的真实限额，所以不能只信它）。
    quota_cooldown: Arc<Mutex<std::collections::HashMap<String, i64>>>,
    /// 本进程实际监听端口。debug 可通过环境变量覆盖，不写入用户设置。
    listen_port: u16,
}

static ACTIVE_PROXY_STATE: std::sync::LazyLock<Mutex<Option<std::sync::Weak<ProxyState>>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

/// Fire-and-forget metadata prewarm for the current or newly selected Google account.
/// This shares the exact ST cache and HTTP pool used by inference and never calls generateContent.
pub fn request_antigravity_prewarm(account_id: Option<String>) {
    let state = ACTIVE_PROXY_STATE
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref()?.upgrade());
    let Some(state) = state else {
        return;
    };
    tauri::async_runtime::spawn(async move {
        let started = std::time::Instant::now();
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            prewarm_antigravity_account(&state, account_id),
        )
        .await
        {
            Ok(Ok(id)) => println!(
                "[GooglePrewarm] account={} ready in {}ms",
                id,
                started.elapsed().as_millis()
            ),
            Ok(Err(error)) => eprintln!("[GooglePrewarm] skipped: {error}"),
            Err(_) => eprintln!("[GooglePrewarm] metadata warmup timed out"),
        }
    });
}

fn google_prewarm_target(store: &AccountStore, requested: Option<&str>) -> Option<String> {
    if store.settings.remote_mode != "client" || !store.settings.proxy_enabled {
        return None;
    }
    let current = store.settings.current_antigravity_account_id.as_deref()?;
    if requested.is_some_and(|id| id != current) {
        return None;
    }
    let account = store.accounts.get(current)?;
    (account.is_antigravity_oauth()
        && !account.is_banned
        && !account.is_logged_out
        && !account.is_token_invalid)
        .then(|| current.to_string())
}

async fn prewarm_antigravity_account(
    state: &ProxyState,
    account_id: Option<String>,
) -> Result<String, String> {
    let (id, primary, fallback, secret) = {
        let store = state.store.lock().map_err(|error| error.to_string())?;
        let id = google_prewarm_target(&store, account_id.as_deref())
            .ok_or("no eligible current Google account")?;
        let (primary, fallback) = antigravity_remote_urls(&store);
        (
            id,
            primary,
            fallback,
            store.settings.remote_shared_secret.clone(),
        )
    };
    let lease = match remote_antigravity_token_cache_get(&id) {
        Some(lease) => lease,
        None => {
            if secret.is_empty() {
                return Err("missing Mini Server secret".into());
            }
            let base = crate::remote_client::resolve_base_url(&primary, &fallback).await?;
            let leased =
                crate::remote_client::fetch_antigravity_token(&base, &secret, &id, false).await?;
            let entry = RemoteAntigravityTokenCacheEntry {
                access_token: leased.access_token,
                project_id: leased.project_id,
                expires_at: leased
                    .expires_at
                    .as_deref()
                    .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
                    .map(|value| value.with_timezone(&Utc))
                    .ok_or("Mini Server Google lease has invalid expiry")?,
            };
            remote_antigravity_token_cache_put(&id, entry.clone());
            entry
        }
    };
    let client = antigravity_http_client(state, &id)?;
    let user_agent = crate::antigravity::native::request_user_agent(&client).await;
    let response = client
        .post(crate::antigravity::native::FETCH_MODELS_URL)
        .bearer_auth(&lease.access_token)
        .header("content-type", "application/json")
        .header("user-agent", user_agent)
        .json(&serde_json::json!({"project":lease.project_id}))
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("metadata returned HTTP {}", response.status()));
    }
    let _ = response.bytes().await.map_err(|error| error.to_string())?;
    Ok(id)
}

pub fn effective_listen_port(configured: u16) -> u16 {
    std::env::var("CODEX_SWITCHER_PROXY_PORT_OVERRIDE")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or(configured)
}

/// 启动代理服务器
pub fn start(
    store: Arc<Mutex<AccountStore>>,
    port: u16,
    allow_lan: bool,
    app_handle: tauri::AppHandle,
    stats: Arc<ProxyStats>,
    tracker: Arc<TokenTracker>,
    ws_disconnect: Arc<tokio::sync::Notify>,
    switch_logger: Arc<SwitchLogger>,
    session_affinity: Arc<SessionAffinity>,
    session_routes: Arc<Mutex<SessionRoutesStore>>,
) -> tauri::async_runtime::JoinHandle<()> {
    let port = effective_listen_port(port);
    tauri::async_runtime::spawn(async move {
        let addr = if allow_lan {
            SocketAddr::from(([0, 0, 0, 0], port))
        } else {
            SocketAddr::from(([127, 0, 0, 1], port))
        };
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[Proxy] 绑定端口 {} 失败: {}", port, e);
                return;
            }
        };

        println!("[Proxy] 代理服务器已启动，监听 {}:{}", addr.ip(), port);

        let client = Client::builder()
            .build()
            .expect("[Proxy] 构建 reqwest Client 失败");

        let state = Arc::new(ProxyState {
            store,
            client,
            antigravity_clients: Mutex::new(std::collections::HashMap::new()),
            app_handle,
            switching: AtomicBool::new(false),
            stats,
            tracker,
            ws_disconnect,
            switch_logger,
            session_affinity,
            session_routes,
            quota_cooldown: Arc::new(Mutex::new(std::collections::HashMap::new())),
            listen_port: port,
        });
        if let Ok(mut active) = ACTIVE_PROXY_STATE.lock() {
            *active = Some(Arc::downgrade(&state));
        }
        request_antigravity_prewarm(None);

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[Proxy] accept 失败: {}", e);
                    continue;
                }
            };

            let state = state.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req| {
                    let state = state.clone();
                    handle_request(state, req)
                });

                if let Err(e) = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await
                {
                    if !e.is_incomplete_message() {
                        eprintln!("[Proxy] 连接 {} 错误: {}", peer_addr, e);
                    }
                }
            });
        }
    })
}

// ────────────────────────────────────────────────────────────────
// Token 管理
// ────────────────────────────────────────────────────────────────

/// 获取当前账号最新的 access_token + 认证模式
///
/// 默认：从本地 store + ~/.codex/auth.json 回读最新值。
/// client 模式：从 Server 拉取新鲜 token，回写本地 store；失败则回退本地。
///
/// 返回 (token, is_chatgpt_auth)
async fn get_current_token(state: &ProxyState) -> Result<(String, bool), String> {
    // 1) 从 store 取一小段快照，尽快释放锁
    let (current_id, remote_mode, primary, fallback, secret, current_is_relay) = {
        let store = state.store.lock().map_err(|e| e.to_string())?;
        let id = store
            .current
            .clone()
            .or_else(|| crate::relay_catalog::relay_only_account_id(&store))
            .ok_or("没有激活的账号")?;
        let current_is_relay = store
            .accounts
            .get(&id)
            .is_some_and(|account| account.is_relay());
        (
            id,
            store.settings.remote_mode.clone(),
            store.settings.remote_server_url.clone(),
            store.settings.remote_server_url_fallback.clone(),
            store.settings.remote_shared_secret.clone(),
            current_is_relay,
        )
    };

    // 2) client 模式：优先命中本地短缓存；miss 时去 Server 拿新鲜 token
    if remote_mode == "client" && !current_is_relay && !secret.is_empty() {
        if let Some((tok, is_chatgpt)) = remote_token_cache_get(&current_id) {
            return Ok((tok, is_chatgpt));
        }
        match crate::remote_client::resolve_base_url(&primary, &fallback).await {
            Ok(base) => {
                match crate::remote_client::fetch_token(&base, &secret, &current_id).await {
                    Ok(t) => {
                        // 回写本地 store，方便 UI 显示一致、quota 等字段也能看到
                        if let Ok(mut store) = state.store.lock() {
                            store.sync_account_from_auth_json(&current_id, t.auth_json.clone());
                            let _ = store.save();
                        }
                        // 用 Server 的新鲜 auth_json 强制覆写本机 ~/.codex/auth.json
                        // 目的：让本机 Codex CLI 永远读到新鲜 access_token，避免它自己触发 oauth refresh
                        // 使 refresh_token 在两端分叉。
                        // 用 extended_expiry 版本：把 expires_at 顶到 +24h，codex 永远不会主动 refresh。
                        // anchor 设置时跳过非 anchor 账号的写盘（保护手机 bridge 的 disk 镜像）
                        write_codex_auth_respecting_anchor(state, &current_id, &t.auth_json);
                        if let Some(tok) = AccountStore::extract_access_token(&t.auth_json) {
                            let is_chatgpt = tok.starts_with("eyJ");
                            remote_token_cache_put(&current_id, &tok, is_chatgpt);
                            return Ok((tok, is_chatgpt));
                        }
                        eprintln!("[Proxy] Server 返回的 auth_json 里没有 access_token");
                    }
                    Err(e) => eprintln!("[Proxy] client 模式 fetch_token 失败，回退本地: {}", e),
                }
            }
            Err(e) => eprintln!("[Proxy] client 模式 Server 不可达，回退本地: {}", e),
        }
    }

    // 3) 默认路径：本地 store + ~/.codex/auth.json
    let mut store = state.store.lock().map_err(|e| e.to_string())?;
    // Relay 账号不与 disk auth.json 同步（disk 是 OAuth 身份，Relay 没 uid，
    // 每次 sync 都会被 sync_account_from_auth_json_inner 的身份校验拒绝并刷一行 log）
    let current_is_relay = store
        .accounts
        .get(&current_id)
        .map(|a| a.is_relay())
        .unwrap_or(false);
    if !current_is_relay {
        if let Ok(disk_auth) = AccountStore::read_codex_auth() {
            if store.sync_account_from_auth_json(&current_id, disk_auth) {
                let _ = store.save();
            }
        }
    }
    let account = store.accounts.get(&current_id).ok_or("当前账号不存在")?;
    let token = AccountStore::extract_access_token(&account.auth_json)
        .ok_or_else(|| "当前账号缺少 access_token".to_string())?;
    let is_chatgpt = token.starts_with("eyJ");
    Ok((token, is_chatgpt))
}

/// 优先按 session affinity 找一个健康的绑定账号；若 binding 还在并指向健康号 → 用它的 token；
/// 否则落回 current。**不修改 store.current**，纯本次请求级别的 token override。
///
/// 返回 (token, is_chatgpt, account_id_used, hard_routed)
/// - account_id 给 end_signal 记账用
/// - hard_routed=true 表示命中用户主动定义的"硬路由"（session_routes），
///   上层在 401/429 时应跳过 try_switch_and_retry / silent_refresh_current，
///   把上游错误原样透回（严格模式）。
async fn resolve_token_with_affinity(
    state: &ProxyState,
    session_key: Option<&str>,
) -> Result<(String, bool, Option<String>, bool), String> {
    let Some(sk) = session_key else {
        let (tok, is_cgpt) = get_current_token(state).await?;
        let cur = state.store.lock().ok().and_then(|s| {
            s.current
                .clone()
                .or_else(|| crate::relay_catalog::relay_only_account_id(&s))
        });
        return Ok((tok, is_cgpt, cur, false));
    };

    // 0) 用户级硬路由优先：session_id 命中 enabled route → 强制用绑定账号 token，
    //    即使账号被标 banned/logged_out 也照打（让上游回 401/403），不触发自动切号。
    let hard_route_hit: Option<(String, String, String)> = {
        let mut routes = state
            .session_routes
            .lock()
            .map_err(|e| format!("session_routes lock: {}", e))?;
        if let Some(route) = routes.find_enabled_by_session(sk) {
            let route_id = route.id.clone();
            let account_id = route.account_id.clone();
            // 取出 token + account name（用同一把 store lock，避免半路被切号）
            let pair = {
                let store = state.store.lock().map_err(|e| e.to_string())?;
                match store.accounts.get(&account_id) {
                    Some(acc) => match AccountStore::extract_access_token(&acc.auth_json) {
                        Some(tok) => Some((tok, acc.name.clone())),
                        None => {
                            eprintln!(
                                "[Proxy] Hard route 命中 {} → {}，但账号缺 access_token；按策略仍透传请求",
                                sk, account_id
                            );
                            None
                        }
                    },
                    None => {
                        eprintln!(
                            "[Proxy] Hard route 命中 {} → {}，但账号不存在；落回普通选号",
                            sk, account_id
                        );
                        None
                    }
                }
            };
            if let Some((token, name)) = pair {
                // 即使路由的账号已被标 banned/logged_out 也继续——严格模式由用户负责
                routes.record_hit(&route_id);
                let _ = routes.save();
                drop(routes);
                let is_chatgpt = token.starts_with("eyJ");
                println!("[Proxy] Hard route hit: {} → {}", sk, name);
                Some((token, account_id, name))
            } else {
                None
            }
        } else {
            None
        }
    };
    if let Some((token, account_id, _name)) = hard_route_hit {
        let is_chatgpt = token.starts_with("eyJ");
        return Ok((token, is_chatgpt, Some(account_id), true));
    }

    // 1) 先看绑定的号是否健康（不依赖 quota，因为 cached_quota 可能滞后；只看 banned/logged_out/token_invalid）
    // 此外：当 current 不是 Relay 但 binding 指向 Relay 时，按 relay_auto_switch_in 决定是否
    // 用这条 binding——默认 false 即"不切到 Relay"，避免 affinity 把订阅号会话偷偷拉回 Relay 扣余额。
    let bound_account = {
        let store = state.store.lock().map_err(|e| e.to_string())?;
        let cur = store.current.clone();
        let cur_is_relay = cur
            .as_deref()
            .and_then(|id| store.accounts.get(id))
            .map(|a| a.is_relay())
            .unwrap_or(false);
        let allow_in = store.settings.relay_auto_switch_in;
        let bid = state.session_affinity.lookup(sk, |id| {
            store
                .accounts
                .get(id)
                .map(|a| {
                    // 基础健康：没被打三个 flag
                    let basic_ok = !a.is_banned && !a.is_logged_out && !a.is_token_invalid;
                    if !basic_ok {
                        return false;
                    }
                    // Relay 没有 5h/周配额概念，跳过额度检查
                    if a.is_relay() {
                        return true;
                    }
                    // 5h / 周配额耗尽时也认为不健康 —— 否则 ChatGPT 上游会做
                    // 静默 mid-stream RST（不是干净 429），codex 看到 transport error
                    // 反复重连 5/5 仍失败。把这种"软失效"也从 affinity 候选剔除。
                    match a.cached_quota.as_ref() {
                        Some(q) => q.has_usable_quota(),
                        None => true, // 没缓存就给个 benefit of doubt
                    }
                })
                .unwrap_or(false)
        });
        match bid {
            Some(id) if Some(&id) != cur.as_ref() => {
                let bound_is_relay = store
                    .accounts
                    .get(&id)
                    .map(|a| a.is_relay())
                    .unwrap_or(false);
                if !allow_in && !cur_is_relay && bound_is_relay {
                    println!(
                        "[Proxy] affinity binding 指向 Relay 但 current 不是 Relay 且 relay_auto_switch_in=false，忽略 binding"
                    );
                    None
                } else {
                    Some(id)
                }
            }
            _ => None,
        }
    };

    if let Some(account_id) = bound_account {
        let token = {
            let store = state.store.lock().map_err(|e| e.to_string())?;
            let acc = store
                .accounts
                .get(&account_id)
                .ok_or_else(|| "session 绑定账号不存在".to_string())?;
            AccountStore::extract_access_token(&acc.auth_json)
                .ok_or_else(|| "session 绑定账号缺 access_token".to_string())?
        };
        let is_chatgpt = token.starts_with("eyJ");
        println!("[Proxy] Session affinity hit: {} → {}", sk, account_id);
        return Ok((token, is_chatgpt, Some(account_id), false));
    }

    let (tok, is_cgpt) = get_current_token(state).await?;
    let cur = state.store.lock().ok().and_then(|s| {
        s.current
            .clone()
            .or_else(|| crate::relay_catalog::relay_only_account_id(&s))
    });
    Ok((tok, is_cgpt, cur, false))
}

/// 根据账号类型选定上游 URL 和 Host header。
///
/// - `is_chatgpt=true` → ChatGPT 订阅那条路径（去掉 `/v1` 前缀）
/// - `is_chatgpt=false` + `relay_base_url=Some(b)` → 中转站 b + 原始 path
/// - `is_chatgpt=false` + `relay_base_url=None` → 官方 api.openai.com + 原始 path
fn get_upstream(
    is_chatgpt: bool,
    relay_base_url: Option<&str>,
    path_and_query: &str,
) -> (String, String) {
    if is_chatgpt {
        // 客户端路径: /v1/responses (因为 OPENAI_BASE_URL 带 /v1)
        // ChatGPT 上游: /backend-api/codex/responses (不含 /v1)
        let path = path_and_query.strip_prefix("/v1").unwrap_or(path_and_query);
        let url = format!("{}{}", CHATGPT_ORIGIN, path);
        (url, CHATGPT_HOST.to_string())
    } else if let Some(base) = relay_base_url {
        // 中转站: 用账号上的 base_url + 原始 path（保留 /v1 前缀）
        let base = base.trim_end_matches('/');
        let host = url::Url::parse(base)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| API_HOST.to_string());
        (format!("{}{}", base, path_and_query), host)
    } else {
        // 官方 API key: 转发到 api.openai.com + 原始路径（保留 /v1）
        let url = format!("{}{}", API_ORIGIN, path_and_query);
        (url, API_HOST.to_string())
    }
}

/// 从 store 取指定账号的 relay_base_url（仅 Relay 类型；其它返回 None）。
fn account_relay_base_url(state: &ProxyState, account_id: &str) -> Option<String> {
    let store = state.store.lock().ok()?;
    let acc = store.accounts.get(account_id)?;
    if acc.is_relay() {
        acc.relay_base_url.clone()
    } else {
        None
    }
}

/// 中转站请求路由信息：当 store.current 是 Relay 时返回 Some。
#[derive(Debug, Clone)]
struct RelayRoute {
    #[allow(dead_code)]
    account_id: String,
    model_map: Option<std::collections::HashMap<String, String>>,
    model_fallback: Option<String>,
    /// `"responses"`（默认 / 上游原生）或 `"chat_completions"`（GLM 走翻译）
    protocol: String,
    /// Relay 配的 API key（chat_completions 模式下用作上游 Authorization）
    api_key: Option<String>,
    /// Relay base_url，便于在 chat_completions 模式下重写为 `<base>/chat/completions`
    base_url: Option<String>,
}

#[derive(Debug, Clone)]
struct AntigravityRoute {
    account_id: String,
    selected_at_start: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    project_id: String,
    expires_at: Option<chrono::DateTime<Utc>>,
    oauth_client_id: Option<String>,
    oauth_client_secret: Option<String>,
}

fn request_model(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .get("model")?
        .as_str()
        .map(ToOwned::to_owned)
}

fn decode_request_body_for_routing(
    headers: &hyper::HeaderMap,
    body: &Bytes,
) -> Result<Bytes, String> {
    let encoding = headers
        .get(hyper::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_ascii_lowercase());
    match encoding.as_deref() {
        Some("zstd") | Some("x-zstd") => zstd::decode_all(body.as_ref())
            .map(Bytes::from)
            .map_err(|error| format!("zstd request decompression failed: {error}")),
        Some("gzip") | Some("x-gzip") => {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(body.as_ref());
            let mut decoded = Vec::with_capacity(body.len().saturating_mul(4));
            decoder
                .read_to_end(&mut decoded)
                .map(|_| Bytes::from(decoded))
                .map_err(|error| format!("gzip request decompression failed: {error}"))
        }
        Some("deflate") => {
            use std::io::Read;
            let mut decoder = flate2::read::DeflateDecoder::new(body.as_ref());
            let mut decoded = Vec::with_capacity(body.len().saturating_mul(4));
            decoder
                .read_to_end(&mut decoded)
                .map(|_| Bytes::from(decoded))
                .map_err(|error| format!("deflate request decompression failed: {error}"))
        }
        _ => Ok(body.clone()),
    }
}

fn antigravity_routes(state: &ProxyState, model_id: &str) -> Vec<AntigravityRoute> {
    let Ok(store) = state.store.lock() else {
        return Vec::new();
    };
    antigravity_routes_from_store(&store, model_id)
}

fn antigravity_routes_from_store(store: &AccountStore, model_id: &str) -> Vec<AntigravityRoute> {
    let client_mode = store.settings.remote_mode == "client";
    let selected_id = store.settings.current_antigravity_account_id.as_deref();
    let mut routes: Vec<(bool, f64, Option<chrono::DateTime<Utc>>, AntigravityRoute)> = store
        .accounts
        .values()
        .filter(|account| {
            account.effective_kind() == AccountKind::AntigravityOauth
                && !account.is_banned
                && !account.is_logged_out
                && !account.is_token_invalid
        })
        .filter_map(|account| {
            let quota_score = crate::antigravity::quota::model_candidate_score(
                &account.auth_json,
                model_id,
                Utc::now(),
            )?;
            if let Some(quotas) = account
                .auth_json
                .get("model_quotas")
                .and_then(serde_json::Value::as_object)
            {
                if !quotas.is_empty() && !quotas.contains_key(model_id) {
                    return None;
                }
            }
            let tokens = account.auth_json.get("tokens");
            let access_token = tokens
                .and_then(|tokens| tokens.get("access_token"))
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned);
            let refresh_token = tokens
                .and_then(|tokens| tokens.get("refresh_token"))
                .and_then(serde_json::Value::as_str)
                .or(account.refresh_token.as_deref())
                .map(ToOwned::to_owned);
            if !client_mode && (access_token.is_none() || refresh_token.is_none()) {
                return None;
            }
            Some((
                selected_id == Some(account.id.as_str()),
                quota_score,
                account.last_used,
                AntigravityRoute {
                    account_id: account.id.clone(),
                    selected_at_start: selected_id.map(ToOwned::to_owned),
                    access_token,
                    refresh_token,
                    project_id: account.auth_json.get("project_id")?.as_str()?.to_string(),
                    expires_at: tokens
                        .and_then(|tokens| tokens.get("expires_at"))
                        .and_then(serde_json::Value::as_str)
                        .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
                        .map(|value| value.with_timezone(&Utc)),
                    oauth_client_id: account
                        .auth_json
                        .pointer("/oauth_client/client_id")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned),
                    oauth_client_secret: account
                        .auth_json
                        .pointer("/oauth_client/client_secret")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned),
                },
            ))
        })
        .collect();
    routes.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| {
                right
                    .1
                    .partial_cmp(&left.1)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| left.2.cmp(&right.2))
    });
    routes.into_iter().map(|(_, _, _, route)| route).collect()
}

fn has_antigravity_account(state: &ProxyState) -> bool {
    state
        .store
        .lock()
        .map(|store| {
            store.accounts.values().any(|account| {
                account.effective_kind() == AccountKind::AntigravityOauth
                    && !account.is_banned
                    && !account.is_logged_out
                    && !account.is_token_invalid
            })
        })
        .unwrap_or(false)
}

fn antigravity_models_for_state(state: &ProxyState) -> Vec<crate::antigravity::AntigravityModel> {
    state
        .store
        .lock()
        .map(|store| antigravity_models_from_store(&store))
        .unwrap_or_default()
}

fn antigravity_models_from_store(
    store: &AccountStore,
) -> Vec<crate::antigravity::AntigravityModel> {
    let live_ids = store
        .accounts
        .values()
        .filter(|account| {
            account.is_antigravity_oauth()
                && !account.is_logged_out
                && !account.is_banned
                && !account.is_token_invalid
        })
        .flat_map(|account| {
            crate::antigravity::quota::read_model_quotas(&account.auth_json).into_keys()
        });
    crate::antigravity::models::catalog_from_live_ids(live_ids)
}

fn antigravity_model_available(state: &ProxyState, id: &str) -> bool {
    antigravity_models_for_state(state)
        .iter()
        .any(|model| model.id == id)
}

fn antigravity_remote_urls(store: &AccountStore) -> (String, String) {
    match std::env::var("CODEX_SWITCHER_ANTIGRAVITY_SERVER_URL_OVERRIDE") {
        Ok(url) if !url.trim().is_empty() => (url, String::new()),
        _ => (
            store.settings.remote_server_url.clone(),
            store.settings.remote_server_url_fallback.clone(),
        ),
    }
}

async fn refresh_antigravity_route_if_needed(
    state: &ProxyState,
    mut route: AntigravityRoute,
) -> Result<AntigravityRoute, String> {
    let (remote_mode, primary, fallback, secret) = {
        let store = state.store.lock().map_err(|error| error.to_string())?;
        let (primary, fallback) = antigravity_remote_urls(&store);
        (
            store.settings.remote_mode.clone(),
            primary,
            fallback,
            store.settings.remote_shared_secret.clone(),
        )
    };
    if remote_mode == "client" {
        if let Some(cached) = remote_antigravity_token_cache_get(&route.account_id) {
            route.access_token = Some(cached.access_token);
            route.project_id = cached.project_id;
            route.expires_at = Some(cached.expires_at);
            return Ok(route);
        }
        if secret.is_empty() {
            return Err("Client mode has no remote_shared_secret for Google token lease".into());
        }
        let base = crate::remote_client::resolve_base_url(&primary, &fallback).await?;
        let leased =
            crate::remote_client::fetch_antigravity_token(&base, &secret, &route.account_id, false)
                .await?;
        let expires_at = leased
            .expires_at
            .as_deref()
            .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
            .map(|value| value.with_timezone(&Utc))
            .ok_or_else(|| "Server Google token lease has no valid expires_at".to_string())?;
        let cached = RemoteAntigravityTokenCacheEntry {
            access_token: leased.access_token,
            project_id: leased.project_id,
            expires_at,
        };
        route.access_token = Some(cached.access_token.clone());
        route.project_id = cached.project_id.clone();
        route.expires_at = Some(cached.expires_at);
        remote_antigravity_token_cache_put(&route.account_id, cached);
        return Ok(route);
    }

    let refresh_needed = route
        .expires_at
        .map(|expires| expires <= Utc::now() + chrono::Duration::minutes(5))
        .unwrap_or(true);
    if !refresh_needed {
        return Ok(route);
    }
    let refresh_token = route
        .refresh_token
        .as_deref()
        .ok_or_else(|| "Antigravity account has no refresh token".to_string())?;
    let config = crate::antigravity::oauth::OAuthClientConfig::from_optional(
        route.oauth_client_id.clone(),
        route.oauth_client_secret.clone(),
    );
    let tokens =
        crate::antigravity::oauth::refresh_access_token(&state.client, &config, refresh_token)
            .await?;
    route.access_token = Some(tokens.access_token);
    if let Some(refresh_token) = tokens.refresh_token {
        route.refresh_token = Some(refresh_token);
    }
    route.expires_at = Some(Utc::now() + chrono::Duration::seconds(tokens.expires_in));

    let mut store = state.store.lock().map_err(|e| e.to_string())?;
    let account = store
        .accounts
        .get_mut(&route.account_id)
        .ok_or_else(|| "Antigravity account disappeared during refresh".to_string())?;
    account.refresh_token = route.refresh_token.clone();
    if let Some(object) = account.auth_json.as_object_mut() {
        let tokens = object
            .entry("tokens")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(tokens) = tokens.as_object_mut() {
            tokens.insert(
                "access_token".to_string(),
                serde_json::Value::String(route.access_token.clone().unwrap_or_default()),
            );
            if let Some(refresh_token) = route.refresh_token.clone() {
                tokens.insert(
                    "refresh_token".to_string(),
                    serde_json::Value::String(refresh_token),
                );
            }
            if let Some(expires_at) = route.expires_at {
                tokens.insert(
                    "expires_at".to_string(),
                    serde_json::Value::String(expires_at.to_rfc3339()),
                );
            }
        }
        object.insert(
            "last_refresh".to_string(),
            serde_json::Value::String(Utc::now().to_rfc3339()),
        );
    }
    store.save()?;
    Ok(route)
}

async fn force_remote_antigravity_route(
    state: &ProxyState,
    mut route: AntigravityRoute,
) -> Result<AntigravityRoute, String> {
    let (primary, fallback, secret) = {
        let store = state.store.lock().map_err(|error| error.to_string())?;
        if store.settings.remote_mode != "client" {
            return Err("not in client mode".to_string());
        }
        let (primary, fallback) = antigravity_remote_urls(&store);
        (
            primary,
            fallback,
            store.settings.remote_shared_secret.clone(),
        )
    };
    let base = crate::remote_client::resolve_base_url(&primary, &fallback).await?;
    let leased =
        crate::remote_client::fetch_antigravity_token(&base, &secret, &route.account_id, true)
            .await?;
    let expires_at = leased
        .expires_at
        .as_deref()
        .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
        .map(|value| value.with_timezone(&Utc))
        .ok_or_else(|| "Server Google token lease has no valid expires_at".to_string())?;
    let cached = RemoteAntigravityTokenCacheEntry {
        access_token: leased.access_token,
        project_id: leased.project_id,
        expires_at,
    };
    route.access_token = Some(cached.access_token.clone());
    route.project_id = cached.project_id.clone();
    route.expires_at = Some(cached.expires_at);
    remote_antigravity_token_cache_put(&route.account_id, cached);
    Ok(route)
}

fn antigravity_http_client(state: &ProxyState, account_id: &str) -> Result<Client, String> {
    let mut clients = state
        .antigravity_clients
        .lock()
        .map_err(|error| error.to_string())?;
    if let Some(client) = clients.get(account_id) {
        return Ok(client.clone());
    }
    let client = crate::antigravity::native::build_http_client()?;
    clients.insert(account_id.to_string(), client.clone());
    Ok(client)
}

async fn handle_antigravity_response(
    state: Arc<ProxyState>,
    method: Method,
    path_and_query: &str,
    body: Bytes,
) -> Response<ProxyBody> {
    let path = path_and_query.split('?').next().unwrap_or("");
    if method != Method::POST || !(path == "/v1/responses" || path.ends_with("/responses")) {
        return error_response(
            StatusCode::NOT_FOUND,
            "Antigravity route only supports /v1/responses",
        );
    }
    let model = request_model(&body).unwrap_or_default();
    let stream = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| value.get("stream").and_then(serde_json::Value::as_bool))
        .unwrap_or(false);
    let routes = antigravity_routes(&state, &model);
    if routes.is_empty() {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "No Google account has quota for this Antigravity model",
        );
    }
    let mut last_error = "Antigravity request failed".to_string();
    let mut last_status = StatusCode::BAD_GATEWAY;
    for route in routes {
        last_status = StatusCode::BAD_GATEWAY;
        let mut route = match refresh_antigravity_route_if_needed(&state, route).await {
            Ok(route) => route,
            Err(error) => {
                last_error = error;
                continue;
            }
        };
        let (payload, mut translator_state) =
            match crate::antigravity::translate::responses_to_antigravity(
                &body,
                &model,
                &route.project_id,
            ) {
                Ok(value) => value,
                Err(error) => return error_response(StatusCode::BAD_REQUEST, &error),
            };
        let antigravity_client = match antigravity_http_client(&state, &route.account_id) {
            Ok(client) => client,
            Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &error),
        };
        let user_agent = crate::antigravity::native::request_user_agent(&antigravity_client).await;
        let endpoint = if stream {
            crate::antigravity::native::STREAM_URL
        } else {
            crate::antigravity::native::GENERATE_URL
        };
        let mut response = match antigravity_client
            .post(endpoint)
            .bearer_auth(route.access_token.as_deref().unwrap_or_default())
            .header("content-type", "application/json")
            .header("user-agent", user_agent)
            .body(payload.clone())
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                last_error = format!("Antigravity request failed: {error}");
                continue;
            }
        };
        if response.status() == reqwest::StatusCode::UNAUTHORIZED && route.refresh_token.is_none() {
            remote_antigravity_token_cache_remove(&route.account_id);
            route = match force_remote_antigravity_route(&state, route).await {
                Ok(route) => route,
                Err(error) => {
                    last_error = format!("Server Google token force refresh failed: {error}");
                    continue;
                }
            };
            response = match antigravity_client
                .post(endpoint)
                .bearer_auth(route.access_token.as_deref().unwrap_or_default())
                .header("content-type", "application/json")
                .header(
                    "user-agent",
                    crate::antigravity::native::request_user_agent(&antigravity_client).await,
                )
                .body(payload)
                .send()
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    last_error = format!("Antigravity retry failed: {error}");
                    continue;
                }
            };
        }
        let status = response.status();
        if status.as_u16() == 429 {
            last_status = StatusCode::TOO_MANY_REQUESTS;
            let _ = response.bytes().await;
            if let Ok(mut store) = state.store.lock() {
                if let Some(account) = store.accounts.get_mut(&route.account_id) {
                    crate::antigravity::quota::mark_model_exhausted(&mut account.auth_json, &model);
                }
                let _ = store.save();
            }
            last_error = format!("Google account exhausted quota for {model}");
            continue;
        }
        if !status.is_success() {
            last_status = status;
            let error_body = response.text().await.unwrap_or_default();
            let preview: String = error_body.chars().take(500).collect();
            last_error = format!("Antigravity upstream returned HTTP {status}: {preview}");
            // Invalid request shape is not an account problem. Do not send the
            // same malformed tool request across every Google identity.
            if status == reqwest::StatusCode::BAD_REQUEST {
                return error_response(StatusCode::BAD_REQUEST, &last_error);
            }
            continue;
        }
        let selection_changed = if let Ok(mut store) = state.store.lock() {
            let changed = store.adopt_antigravity_after_success(
                &route.account_id,
                route.selected_at_start.as_deref(),
            );
            if changed {
                let _ = store.save();
            }
            changed
        } else {
            false
        };
        if selection_changed {
            let _ = state.app_handle.emit("accounts-updated", ());
        }
        schedule_antigravity_success_refresh(
            state.clone(),
            antigravity_client.clone(),
            route.clone(),
        );
        if stream {
            let mut headers = response.headers().clone();
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("text/event-stream"),
            );
            headers.insert(
                reqwest::header::CACHE_CONTROL,
                reqwest::header::HeaderValue::from_static("no-cache"),
            );
            let status = response.status();
            let translated_stream = antigravity_codex_stream(response, translator_state, model);
            return build_stream_response_from_parts(
                status,
                headers,
                Bytes::new(),
                translated_stream,
                Some(state.tracker.clone()),
                None,
            );
        }
        let raw = match response.bytes().await {
            Ok(bytes) => bytes,
            Err(error) => {
                last_error = format!("Antigravity response read failed: {error}");
                continue;
            }
        };
        let translated = match crate::antigravity::translate::antigravity_response_to_codex(
            &raw,
            &mut translator_state,
            &model,
            stream,
        ) {
            Ok(value) => value,
            Err(error) => return error_response(StatusCode::BAD_GATEWAY, &error),
        };
        return Response::builder()
            .status(StatusCode::OK)
            .header(
                "content-type",
                if stream {
                    "text/event-stream"
                } else {
                    "application/json"
                },
            )
            .header("cache-control", "no-cache")
            .body(full_body(Bytes::from(translated)))
            .unwrap_or_else(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Antigravity response build failed",
                )
            });
    }
    error_response(last_status, &last_error)
}

fn schedule_antigravity_success_refresh(
    state: Arc<ProxyState>,
    client: Client,
    route: AntigravityRoute,
) {
    tokio::spawn(async move {
        let latest_quotas = crate::antigravity::quota::fetch_model_quotas(
            &client,
            route.access_token.as_deref().unwrap_or_default(),
            &route.project_id,
        )
        .await
        .ok();
        if let Ok(mut store) = state.store.lock() {
            if let Some(account) = store.accounts.get_mut(&route.account_id) {
                account.last_used = Some(Utc::now());
                if let Some(ref quotas) = latest_quotas {
                    crate::antigravity::quota::write_model_quotas(&mut account.auth_json, quotas);
                }
            }
            let _ = store.save();
        }
    });
}

struct AntigravityCodexStream {
    upstream: ByteStream,
    buffer: Vec<u8>,
    queued: std::collections::VecDeque<Bytes>,
    translator: crate::relay_translate::TranslatorState,
    model: String,
    upstream_done: bool,
    finalized: bool,
    failed: bool,
    finish_reason: Option<String>,
}

fn antigravity_codex_stream(
    response: reqwest::Response,
    mut translator: crate::relay_translate::TranslatorState,
    model: String,
) -> ByteStream {
    let mut queued = std::collections::VecDeque::new();
    queued.push_back(Bytes::from(crate::relay_translate::emit_google_created(
        &mut translator,
    )));
    let state = AntigravityCodexStream {
        upstream: response.bytes_stream().boxed(),
        buffer: Vec::new(),
        queued,
        translator,
        model,
        upstream_done: false,
        finalized: false,
        failed: false,
        finish_reason: None,
    };
    futures_util::stream::unfold(state, |mut state| async move {
        loop {
            if let Some(bytes) = state.queued.pop_front() {
                return Some((Ok(bytes), state));
            }
            while let Some(data) = pop_sse_data(&mut state.buffer) {
                if data == b"[DONE]" {
                    state.upstream_done = true;
                    if state.finish_reason.is_none() {
                        state.finish_reason = Some("STOP".into());
                    }
                    break;
                }
                match crate::antigravity::translate::inspect_stream_event(&data) {
                    Ok(Some(reason)) => state.finish_reason = Some(reason),
                    Ok(None) => {}
                    Err(error) => {
                        state.failed = true;
                        state.buffer.clear();
                        state
                            .queued
                            .push_back(Bytes::from(crate::relay_translate::emit_failed(
                                &mut state.translator,
                                "upstream_error",
                                &error,
                            )));
                        break;
                    }
                }
                if let Some(chat_chunk) =
                    crate::antigravity::translate::antigravity_sse_event_to_chat_chunk(
                        &data,
                        &state.model,
                    )
                {
                    for event in
                        crate::relay_translate::handle_chunk(&mut state.translator, &chat_chunk)
                    {
                        state.queued.push_back(Bytes::from(event));
                    }
                }
            }
            if let Some(bytes) = state.queued.pop_front() {
                return Some((Ok(bytes), state));
            }
            if state.failed {
                return None;
            }
            if state.upstream_done {
                if !state.finalized {
                    state.finalized = true;
                    let completed = crate::antigravity::translate::finish_codex_stream(
                        &mut state.translator,
                        state.finish_reason.as_deref(),
                    );
                    return Some((Ok(Bytes::from(completed)), state));
                }
                return None;
            }
            match state.upstream.next().await {
                Some(Ok(bytes)) => state.buffer.extend_from_slice(&bytes),
                Some(Err(_error)) => {
                    state.failed = true;
                    let event = crate::relay_translate::emit_failed(
                        &mut state.translator,
                        "upstream_connection_error",
                        "Google stream connection closed before completion",
                    );
                    return Some((Ok(Bytes::from(event)), state));
                }
                None => {
                    state.upstream_done = true;
                    state.buffer.extend_from_slice(b"\n\n");
                }
            }
        }
    })
    .boxed()
}

fn pop_sse_data(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    loop {
        let (end, delimiter_len) = buffer
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|end| (end, 4))
            .or_else(|| {
                buffer
                    .windows(2)
                    .position(|window| window == b"\n\n")
                    .map(|end| (end, 2))
            })?;
        let event: Vec<u8> = buffer.drain(..end).collect();
        buffer.drain(..delimiter_len);
        let mut data = Vec::new();
        for line in event.split(|byte| *byte == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if let Some(value) = line.strip_prefix(b"data:") {
                if !data.is_empty() {
                    data.push(b'\n');
                }
                data.extend_from_slice(value.strip_prefix(b" ").unwrap_or(value));
            }
        }
        if !data.is_empty() {
            return Some(data);
        }
        // Skip comments/heartbeats without hiding a subsequent event already buffered.
    }
}

fn antigravity_codex_catalog_entry(
    model: &crate::antigravity::AntigravityModel,
    template: Option<&serde_json::Value>,
) -> serde_json::Value {
    let default_reasoning_level = model.default_thinking_level;
    let mut entry = template.cloned().unwrap_or_else(|| serde_json::json!({}));
    let Some(object) = entry.as_object_mut() else {
        return serde_json::json!({});
    };
    object.insert("slug".into(), serde_json::json!(model.id));
    object.insert("display_name".into(), serde_json::json!(model.display_name));
    object.insert("description".into(), serde_json::json!(model.description));
    // The native GPT template is borrowed only for catalog shape. None of its
    // system prompt belongs to Google/Claude models: partial phrase stripping
    // previously leaked later "As Codex" paragraphs and scripted their identity.
    object.insert("base_instructions".into(), serde_json::json!(""));
    if let Some(model_messages) = object
        .get_mut("model_messages")
        .and_then(serde_json::Value::as_object_mut)
    {
        model_messages.insert("instructions_template".into(), serde_json::json!(""));
    }
    object.insert(
        "context_window".into(),
        serde_json::json!(model.context_length),
    );
    object.insert(
        "max_context_window".into(),
        serde_json::json!(model.context_length),
    );
    object.insert(
        "max_output_tokens".into(),
        serde_json::json!(model.max_completion_tokens),
    );
    object.insert(
        "input_modalities".into(),
        serde_json::json!(model.input_modalities),
    );
    object.insert(
        "output_modalities".into(),
        serde_json::json!(model.output_modalities),
    );
    object.insert(
        "supported_reasoning_levels".into(),
        serde_json::Value::Array(
            model
                .thinking_levels
                .iter()
                .map(|effort| {
                    serde_json::json!({
                        "effort": effort,
                        "description": format!("Antigravity {effort} thinking"),
                    })
                })
                .collect(),
        ),
    );
    object.insert(
        "default_reasoning_level".into(),
        serde_json::json!(default_reasoning_level),
    );
    object.insert(
        "default_reasoning_summary".into(),
        serde_json::json!("auto"),
    );
    object.insert(
        "supports_parallel_tool_calls".into(),
        serde_json::json!(true),
    );
    object.insert("prefer_websockets".into(), serde_json::json!(true));
    object.insert("supports_websockets".into(), serde_json::json!(true));
    object.insert(
        "supports_image_detail_original".into(),
        serde_json::json!(true),
    );
    object.insert("multi_agent_version".into(), serde_json::json!("v2"));
    object.insert("shell_type".into(), serde_json::json!("shell_command"));
    object.insert("tool_mode".into(), serde_json::Value::Null);
    object.insert("visibility".into(), serde_json::json!("list"));
    object.insert("supported_in_api".into(), serde_json::json!(true));
    object.insert("priority".into(), serde_json::json!(40));
    // Never inherit lifecycle metadata from the native model used as a schema
    // template. Codex Desktop treats a past `upgrade.retirement_at` as a hard
    // disable signal and aborts the turn before any request reaches the proxy.
    object.insert("upgrade".into(), serde_json::Value::Null);
    object.insert("retirement_at".into(), serde_json::Value::Null);
    entry
}

async fn handle_models_with_antigravity(
    state: Arc<ProxyState>,
    req_headers: &hyper::HeaderMap,
    path_and_query: &str,
) -> Response<ProxyBody> {
    // Native relays do not necessarily implement Codex's /models metadata API.
    // If a relay is current, serve its configured catalog locally. The normal
    // ChatGPT-current path below still fetches and preserves the native GPT list.
    let local_relay_catalog = state.store.lock().ok().and_then(|store| {
        let current = store.current.as_ref().and_then(|id| store.accounts.get(id));
        if current.is_some_and(|a| !a.is_relay()) {
            return None;
        }
        let configured = crate::relay_catalog::models(&store);
        if configured.is_empty() {
            return None;
        }
        Some(configured)
    });
    if let Some(configured) = local_relay_catalog {
        let mut models: Vec<serde_json::Value> = configured
            .iter()
            .map(|model| crate::relay_catalog::catalog_entry(model, None))
            .collect();
        if let Ok(store) = state.store.lock() {
            for model in crate::relay_catalog::candidates(&store) {
                let mut entry = crate::relay_catalog::catalog_entry(&model, None);
                entry["visibility"] = serde_json::json!("hide");
                models.push(entry);
            }
        }
        if has_antigravity_account(&state) {
            models.extend(
                crate::antigravity::models::grouped_display_models(&antigravity_models_for_state(
                    &state,
                ))
                .iter()
                .map(|model| antigravity_codex_catalog_entry(model, None)),
            );
        }
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(full_body(Bytes::from(
                serde_json::json!({"models":models}).to_string(),
            )))
            .unwrap();
    }
    let (token, is_chatgpt) = match get_current_token(&state).await {
        Ok(value) => value,
        Err(error) => return error_response(StatusCode::UNAUTHORIZED, &error),
    };
    let (relay_base_url, chatgpt_account_id) = {
        let store = match state.store.lock() {
            Ok(store) => store,
            Err(error) => {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            }
        };
        let account = store
            .current
            .as_deref()
            .and_then(|id| store.accounts.get(id));
        (
            account
                .filter(|account| account.is_relay())
                .and_then(|account| account.relay_base_url.clone()),
            account.and_then(|account| AccountStore::extract_account_id(&account.auth_json)),
        )
    };
    let (url, host) = get_upstream(is_chatgpt, relay_base_url.as_deref(), path_and_query);
    let mut headers = build_upstream_headers(req_headers, &host);
    headers.insert(
        reqwest::header::AUTHORIZATION,
        match reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
            Ok(value) => value,
            Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
        },
    );
    if is_chatgpt {
        if let Some(account_id) = chatgpt_account_id {
            if let Ok(value) = reqwest::header::HeaderValue::from_str(&account_id) {
                headers.insert(
                    reqwest::header::HeaderName::from_static(CHATGPT_ACCOUNT_ID_HEADER),
                    value,
                );
            }
        }
    }
    // This endpoint parses and augments JSON, so do not forward the caller's
    // compression negotiation (the shared passthrough client doesn't decode it).
    headers.insert(
        reqwest::header::ACCEPT_ENCODING,
        reqwest::header::HeaderValue::from_static("identity"),
    );
    let response = match state.client.get(url).headers(headers).send().await {
        Ok(response) => response,
        Err(error) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                &format!("models upstream failed: {error}"),
            )
        }
    };
    let status = response.status();
    let raw = match response.bytes().await {
        Ok(raw) => raw,
        Err(error) => return error_response(StatusCode::BAD_GATEWAY, &error.to_string()),
    };
    if !status.is_success() {
        return Response::builder()
            .status(status.as_u16())
            .header("content-type", "application/json")
            .body(full_body(raw))
            .unwrap_or_else(|_| error_response(StatusCode::BAD_GATEWAY, "models upstream failed"));
    }
    let mut catalog: serde_json::Value = match serde_json::from_slice(&raw) {
        Ok(value) => value,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(full_body(raw))
                .unwrap()
        }
    };
    if has_antigravity_account(&state) {
        if let Some(models) = catalog
            .get_mut("models")
            .and_then(serde_json::Value::as_array_mut)
        {
            let template = models
                .iter()
                .find(|model| {
                    model.get("slug").and_then(serde_json::Value::as_str) == Some("gpt-5.6-luna")
                })
                .or_else(|| {
                    models
                        .iter()
                        .find(|model| model.get("upgrade").is_none_or(serde_json::Value::is_null))
                })
                .cloned()
                .or_else(|| models.first().cloned());
            let existing: std::collections::HashSet<String> = models
                .iter()
                .filter_map(|model| {
                    model
                        .get("slug")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .collect();
            let raw_models = antigravity_models_for_state(&state);
            let grouped = crate::antigravity::models::grouped_display_models(&raw_models);
            let visible: std::collections::HashSet<_> =
                grouped.iter().map(|model| model.id.clone()).collect();
            for model in grouped {
                if !existing.contains(&model.id) {
                    models.push(antigravity_codex_catalog_entry(&model, template.as_ref()));
                }
            }
            for model in raw_models
                .into_iter()
                .filter(|model| !visible.contains(&model.id))
            {
                if !existing.contains(&model.id) {
                    let mut entry = antigravity_codex_catalog_entry(&model, template.as_ref());
                    entry["visibility"] = serde_json::json!("hide");
                    models.push(entry);
                }
            }
        } else if let Some(models) = catalog
            .get_mut("data")
            .and_then(serde_json::Value::as_array_mut)
        {
            let existing: std::collections::HashSet<String> = models
                .iter()
                .filter_map(|model| {
                    model
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .collect();
            for model in crate::antigravity::models::grouped_display_models(
                &antigravity_models_for_state(&state),
            ) {
                if !existing.contains(&model.id) {
                    models.push(serde_json::json!({"id": model.id, "object": "model", "owned_by": "antigravity"}));
                }
            }
        }
    }
    let relay_models = state
        .store
        .lock()
        .map(|s| crate::relay_catalog::models(&s))
        .unwrap_or_default();
    let relay_aliases = state
        .store
        .lock()
        .map(|s| crate::relay_catalog::candidates(&s))
        .unwrap_or_default();
    if let Some(models) = catalog
        .get_mut("models")
        .and_then(serde_json::Value::as_array_mut)
    {
        let template = models.first().cloned();
        for model in &relay_models {
            if !models.iter().any(|entry| {
                entry.get("slug").and_then(serde_json::Value::as_str) == Some(model.slug.as_str())
            }) {
                models.push(crate::relay_catalog::catalog_entry(
                    model,
                    template.as_ref(),
                ));
            }
        }
        for model in &relay_aliases {
            if !models.iter().any(|entry| {
                entry.get("slug").and_then(serde_json::Value::as_str) == Some(model.slug.as_str())
            }) {
                let mut entry = crate::relay_catalog::catalog_entry(model, template.as_ref());
                entry["visibility"] = serde_json::json!("hide");
                models.push(entry);
            }
        }
    } else if let Some(models) = catalog
        .get_mut("data")
        .and_then(serde_json::Value::as_array_mut)
    {
        for model in &relay_models {
            models.push(
                serde_json::json!({"id":model.slug,"object":"model","owned_by":model.account_name}),
            );
        }
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(full_body(Bytes::from(catalog.to_string())))
        .unwrap_or_else(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "models response build failed",
            )
        })
}

fn has_named_relay_models(state: &ProxyState) -> bool {
    state
        .store
        .lock()
        .map(|s| !crate::relay_catalog::models(&s).is_empty())
        .unwrap_or(false)
}

async fn handle_named_relay_response(
    state: Arc<ProxyState>,
    method: Method,
    path: &str,
    req_headers: hyper::HeaderMap,
    body: Bytes,
    slug: &str,
) -> Response<ProxyBody> {
    let path_only = path.split('?').next().unwrap_or("");
    let is_compact = is_responses_compact_path(path);
    if method != Method::POST || (!path_only.ends_with("/responses") && !is_compact) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "Selected relay model requires the Responses API",
        );
    }
    let target = state.store.lock().ok().and_then(|s| {
        let model = crate::relay_catalog::resolve(&s, slug)?;
        let account = s.accounts.get(&model.account_id)?;
        Some((
            model,
            account.relay_base_url.clone()?,
            AccountStore::extract_access_token(&account.auth_json)?,
            account.relay_protocol_or_default().to_string(),
        ))
    });
    let Some((model, base, key, protocol)) = target else {
        // Never silently send a removed/disabled relay model to the ChatGPT account.
        return error_response(
            StatusCode::BAD_REQUEST,
            "Selected relay model is unavailable; check its account, API key and protocol",
        );
    };
    if protocol == "chat_completions" {
        if method != Method::POST || (!path.split('?').next().unwrap_or("").ends_with("/responses") && !is_compact) {
            return error_response(
                StatusCode::BAD_REQUEST,
                "Selected chat relay model requires the Responses API",
            );
        }
        let mut value: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(value) => value,
            Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
        };
        if let Some(object) = value.as_object_mut() {
            object.insert("model".to_string(), serde_json::json!(model.upstream));
        }
        let body = match serde_json::to_vec(&value) {
            Ok(body) => Bytes::from(body),
            Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
        };
        let Some(relay) = relay_route_for_account(&state, &model.account_id) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "Selected chat relay account unavailable",
            );
        };
        // body_for_routing 已经按原始 Content-Encoding 解压过；不要让下游
        // Chat Completions 翻译器看到 zstd/gzip 头后再次解压同一份 JSON。
        let mut relay_headers = req_headers;
        relay_headers.remove(hyper::header::CONTENT_ENCODING);
        relay_headers.remove(hyper::header::CONTENT_LENGTH);
        return handle_chat_completions_relay(
            state,
            relay,
            method,
            path.to_string(),
            relay_headers,
            body,
        )
        .await;
    }
    if method != Method::POST || !path.split('?').next().unwrap_or("").ends_with("/responses") {
        return error_response(
            StatusCode::BAD_REQUEST,
            "Selected relay model requires the Responses API",
        );
    }
    // Fresh headers: do not leak a ChatGPT bearer, account id, cookies or private
    // routing headers to a third-party API. Native Responses body/events pass through.
    let response = match if is_compact {
        crate::relay_catalog::forward_native_compact(&state.client, &base, &key, &body, &model)
            .await
    } else {
        crate::relay_catalog::forward_native(&state.client, &base, &key, &body, &model).await
    } {
        Ok(response) => response,
        Err(error) => return error_response(StatusCode::BAD_GATEWAY, &error),
    };
    if response.status().is_success() {
        if let Ok(mut store) = state.store.lock() {
            if let Some(account) = store.accounts.get_mut(&model.account_id) {
                account.last_used = Some(Utc::now());
            }
            let _ = store.save();
        }
    }
    build_stream_response(response, None, None)
}

fn is_responses_compact_path(path: &str) -> bool {
    path.split('?')
        .next()
        .unwrap_or("")
        .ends_with("/responses/compact")
}

/// 取 store.current 的 Relay 路由信息（仅 Relay 类型；其它 None）。
fn current_relay_route(state: &ProxyState) -> Option<RelayRoute> {
    let store = state.store.lock().ok()?;
    let id = store
        .current
        .clone()
        .or_else(|| crate::relay_catalog::relay_only_account_id(&store))?;
    let acc = store.accounts.get(&id)?;
    if !acc.is_relay() {
        return None;
    }
    Some(RelayRoute {
        account_id: id,
        model_map: acc.relay_model_map.clone(),
        model_fallback: acc.relay_model_fallback.clone(),
        protocol: acc.relay_protocol_or_default().to_string(),
        api_key: AccountStore::extract_access_token(&acc.auth_json),
        base_url: acc.relay_base_url.clone(),
    })
}

/// 按 account_id 直接构造 RelayRoute（hard route 用，跳过 store.current 检查）。
fn relay_route_for_account(state: &ProxyState, account_id: &str) -> Option<RelayRoute> {
    let store = state.store.lock().ok()?;
    let acc = store.accounts.get(account_id)?;
    if !acc.is_relay() {
        return None;
    }
    Some(RelayRoute {
        account_id: account_id.to_string(),
        model_map: acc.relay_model_map.clone(),
        model_fallback: acc.relay_model_fallback.clone(),
        protocol: acc.relay_protocol_or_default().to_string(),
        api_key: AccountStore::extract_access_token(&acc.auth_json),
        base_url: acc.relay_base_url.clone(),
    })
}

/// 从请求 headers + body 提取 session_key，并查 enabled hard route。
/// 命中即记录 hit 并返回 (session_key, account_id)。
///
/// hyper::HeaderMap 跟 reqwest::header::HeaderMap 都是 http::HeaderMap 的别名，
/// 同类型直接传，不需要拷贝转换（之前转换可能因 HeaderName::from_bytes 验证规则
/// 把 codex 的 `session_id`（带 underscore）丢掉，导致路由命中失败）。
fn resolve_hard_route(
    state: &ProxyState,
    body: &[u8],
    headers: &hyper::HeaderMap,
) -> Option<(String, String)> {
    // 显式 fallback：先按 codex 实际发的 session_id / thread_id header 直接抠，
    // 跟 session_affinity 模块兼容（`hdr:` 前缀）。
    //
    // `x-pod-worker-route` 单独排在最前面：它是纯本地路由 key，跟
    // `session-id`/`thread-id` 这两个 pod-worker 也会发的"仿真展示"字段分开——
    // 展示字段每次请求都是新随机 UUID，如果混进这个候选列表且排在路由 key 前面，
    // 会先命中一个永远查不到路由的随机值，导致硬路由失效。
    let sk: Option<String> = (|| -> Option<String> {
        for name in &[
            "x-pod-worker-route",
            "session_id",
            "session-id",
            "x-session-id",
            "thread_id",
        ] {
            if let Some(v) = headers.get(*name).and_then(|v| v.to_str().ok()) {
                if !v.is_empty() {
                    return Some(format!("hdr:{v}"));
                }
            }
        }
        // fallback：还看 body（JSON prompt_cache_key / previous_response_id），
        // 走 session_affinity 已有逻辑
        crate::session_affinity::extract_session_key(body, headers)
    })();
    let sk = sk?;
    // 路由表里存的是 bare session UUID（不带 hdr: / pck: 前缀），lookup 要剥掉前缀
    let raw_session = sk
        .strip_prefix("hdr:")
        .or_else(|| sk.strip_prefix("pck:"))
        .or_else(|| sk.strip_prefix("prev:"))
        .unwrap_or(&sk)
        .to_string();
    let account_id = {
        let mut routes = state.session_routes.lock().ok()?;
        match routes.find_enabled_by_session(&raw_session) {
            Some(r) => {
                let aid = r.account_id.clone();
                let rid = r.id.clone();
                routes.record_hit(&rid);
                let _ = routes.save();
                aid
            }
            None => {
                let known: Vec<String> = routes
                    .routes
                    .values()
                    .filter(|r| r.enabled)
                    .map(|r| r.session_id.clone())
                    .collect();
                println!(
                    "[Proxy] Hard route MISS: incoming session_key={:?} raw={:?} known_routes={:?}",
                    sk, raw_session, known
                );
                return None;
            }
        }
    };
    let acc_name = state
        .store
        .lock()
        .ok()
        .and_then(|s| s.accounts.get(&account_id).map(|a| a.name.clone()))
        .unwrap_or_else(|| account_id.clone());
    println!(
        "[Proxy] Hard route hit: session={} → {} ({})",
        raw_session, account_id, acc_name
    );
    Some((sk, account_id))
}

/// 若 body 是 JSON 且含 `model` 字段，按 `map` / `fallback` 重写。
///
/// 优先级：map 命中 > fallback；都不命中或值跟原值相等 → 原样返回。
///
/// **幂等保证**：函数可能在请求生命周期里被调用多次（顶层 raw body 一次 + 解压
/// 后翻译器入口再一次）。如果当前 model 已经是 map 的某个 value（或正好等于
/// fallback），就跳过——避免出现"o1→deepseek-reasoner 之后再被 fallback 拉回
/// deepseek-chat"这种 double-rewrite 把 reasoner 模型偷偷换成 chat 的 bug。
fn rewrite_model_in_body(
    body: &Bytes,
    map: Option<&std::collections::HashMap<String, String>>,
    fallback: Option<&str>,
) -> Bytes {
    if map.map_or(true, |m| m.is_empty()) && fallback.is_none() {
        return body.clone();
    }
    let mut json: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return body.clone(), // 非 JSON 直接透传（流式上传等）
    };
    let original = match json.get("model").and_then(|v| v.as_str()) {
        Some(m) => m.to_string(),
        None => return body.clone(),
    };

    // 幂等：如果 original 已经是 map 的某个 target value，或就是 fallback，
    // 说明此前已经 rewrite 过；直接返回，不再二次替换。
    let already_target = map
        .map(|m| m.values().any(|v| v == &original))
        .unwrap_or(false)
        || fallback.map_or(false, |f| f == original);
    if already_target {
        return body.clone();
    }

    let target = map
        .and_then(|m| m.get(&original).cloned())
        .or_else(|| fallback.map(String::from));
    if let Some(t) = target {
        if t != original {
            println!("[Proxy] Relay model rewrite: {} → {}", original, t);
            json["model"] = serde_json::Value::String(t);
            return Bytes::from(serde_json::to_vec(&json).unwrap_or_else(|_| body.to_vec()));
        }
    }
    body.clone()
}

/// Normalize standard OpenAI Responses options for ChatGPT's Codex backend.
///
/// Pi and other OpenAI-compatible SDKs legitimately send optional public API
/// fields that `chatgpt.com/backend-api/codex/responses` does not currently
/// accept. They are transport hints rather than prompt content, so dropping
/// them keeps the request semantics and lets the backend apply its defaults.
/// OpenAI-key and third-party Relay requests must bypass this function.
fn normalize_chatgpt_responses_body(
    body: &Bytes,
    path_and_query: &str,
    headers: &reqwest::header::HeaderMap,
) -> Bytes {
    let path = path_and_query.split('?').next().unwrap_or(path_and_query);
    let pi_compat = headers
        .get("x-pi-agent-sdk")
        .and_then(|value| value.to_str().ok())
        .map(|value| value == "1")
        .unwrap_or(false);
    if !pi_compat || (path != "/v1/responses" && path != "/responses") {
        return body.clone();
    }
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return body.clone();
    };
    let Some(object) = value.as_object_mut() else {
        return body.clone();
    };
    let mut changed = false;
    for key in [
        "max_output_tokens",
        "prompt_cache_retention",
        "prompt_cache_options",
    ] {
        changed |= object.remove(key).is_some();
    }
    if !changed {
        return body.clone();
    }
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .unwrap_or_else(|_| body.clone())
}

// ────────────────────────────────────────────────────────────────
// 选号算法（复用 lib.rs 共享评分）
// ────────────────────────────────────────────────────────────────

enum PickResult {
    Found { id: String, token: String },
    Exhausted { earliest_reset: Option<i64> },
}

fn pick_next_account(state: &ProxyState) -> PickResult {
    let store = match state.store.lock() {
        Ok(s) => s,
        Err(_) => {
            return PickResult::Exhausted {
                earliest_reset: None,
            }
        }
    };

    let candidates = crate::score_candidate_accounts(&store);

    if candidates.is_empty() {
        let now = Utc::now().timestamp();
        let mut earliest: Option<i64> = None;
        for account in store.accounts.values() {
            if let Some(q) = &account.cached_quota {
                for r in [q.five_hour_reset_at, q.weekly_reset_at]
                    .into_iter()
                    .flatten()
                {
                    if now < r {
                        earliest = Some(earliest.map_or(r, |e: i64| e.min(r)));
                    }
                }
            }
        }
        return PickResult::Exhausted {
            earliest_reset: earliest,
        };
    }

    // 优先跳过刚撞过 429 的号（cached 5h% 不反映某些模型真实限额，靠冷却兜底）；
    // 若所有候选都在冷却期，退回原列表，别因冷却把池子饿空。
    let filtered: Vec<&(String, String, f64)> = candidates
        .iter()
        .filter(|(id, _, _)| !is_in_cooldown(state, id))
        .collect();
    let id = if filtered.is_empty() {
        &candidates[0].0
    } else {
        &filtered[0].0
    };
    if let Some(account) = store.accounts.get(id) {
        if let Some(token) = AccountStore::extract_access_token(&account.auth_json) {
            return PickResult::Found {
                id: id.clone(),
                token,
            };
        }
    }

    PickResult::Exhausted {
        earliest_reset: None,
    }
}

// ────────────────────────────────────────────────────────────────
// 预防性切号 / 封号检测 / 切号执行
// ────────────────────────────────────────────────────────────────

fn should_preemptive_switch(state: &ProxyState) -> bool {
    let store = match state.store.lock() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let (t5h, tw, fg) = (
        store.settings.proxy_threshold_5h as f64,
        store.settings.proxy_threshold_weekly as f64,
        store.settings.proxy_free_guard as f64,
    );

    if t5h == 0.0 && tw == 0.0 && fg == 0.0 {
        return false;
    }

    let current_id = match &store.current {
        Some(id) => id,
        None => return false,
    };

    let account = match store.accounts.get(current_id) {
        Some(a) => a,
        None => return false,
    };

    // current 是 Relay 时，按设置决定是否允许预切走（401/429/quota 触发）
    if account.is_relay() && !store.settings.relay_auto_switch_out {
        return false;
    }

    if account.is_banned || account.is_token_invalid || account.is_logged_out {
        println!("[Proxy] 发现当前账号被封禁/失效/登出，触发预防性切号");
        return true;
    }

    let quota = match account.cached_quota.as_ref() {
        Some(q) => q,
        None => return false,
    };

    let plan = quota.plan_type.to_lowercase();
    let is_free = plan == "free" || plan == "unknown";

    // 阈值命中前先看：当前号是否还有活跃 session affinity binding。
    // 有的话主动抢切会立刻让进行中的会话掉 prompt cache —— 这种"预防 429"的代价
    // 是 cache cold-start（write 1.25× + 下一轮 input 全价）。让请求自己撞 429
    // 再切才划算（撞 429 时 affinity 也会被 invalidate，行为一致），并且能榨出
    // 当前号最后那一点额度。
    let has_active_session = state.session_affinity.has_active_binding_to(current_id);

    if is_free && fg > 0.0 && quota.five_hour_left < fg {
        if has_active_session {
            return false;
        }
        println!(
            "[Proxy] Free 保护线触发: {:.0}% < {:.0}%",
            quota.five_hour_left, fg
        );
        return true;
    }
    if t5h > 0.0 && quota.five_hour_left < t5h {
        if has_active_session {
            return false;
        }
        println!(
            "[Proxy] 5h 阈值触发: {:.0}% < {:.0}%",
            quota.five_hour_left, t5h
        );
        return true;
    }
    if tw > 0.0 && quota.weekly_left < tw {
        if has_active_session {
            return false;
        }
        println!("[Proxy] 周阈值触发: {:.0}% < {:.0}%", quota.weekly_left, tw);
        return true;
    }
    false
}

fn mark_current_banned(state: &ProxyState) {
    if let Ok(mut store) = state.store.lock() {
        if let Some(current_id) = store.current.clone() {
            // 顺便作废 session affinity 里指向该号的所有 binding
            state.session_affinity.invalidate_account(&current_id);
            if let Some(account) = store.accounts.get_mut(&current_id) {
                account.is_banned = true;
                let name = account.name.clone();
                let _ = store.save();
                println!("[Proxy] 账号 {} 已标记为封号", name);
                let _ = state.app_handle.emit("proxy-account-banned", &name);
                // macOS 系统通知（可配置）
                if cfg!(target_os = "macos") && store.settings.notify_on_switch {
                    let notify_name = name.clone();
                    std::thread::spawn(move || {
                        let _ = std::process::Command::new("osascript")
                            .arg("-e")
                            .arg(format!(
                                "display notification \"{}\" with title \"{}\" subtitle \"{}\"",
                                notify_name,
                                crate::i18n::APP_NAME,
                                crate::i18n::notification_account_banned_subtitle()
                            ))
                            .output();
                    });
                }
            }
        }
    }
}

/// Spark 模型 id（chat_inbound 已把所有 spark 别名归一到这个）。
const SPARK_MODEL_ID: &[u8] = b"gpt-5.3-codex-spark";

/// 请求是否针对 Spark 模型。Spark 是 **Pro 专属的独立子限额**（accounts.json
/// cached_quota.spark），跟基础 5h/周额度是两个池子；gpt-5.5 等走的是基础额度。
/// 所以 Spark 请求 429 只代表 Spark 耗尽，**绝不能据此判定整个账号没额度而切号**——
/// 否则会把同账号上正常的 gpt-5.5 会话一起踢到没额度的号上（用户报的"任务停"根因）。
/// 直接扫 body 里的精确模型 id（chat_inbound 已归一），不解析大 body。
fn request_is_spark_model(body: &[u8]) -> bool {
    body.len() >= SPARK_MODEL_ID.len()
        && body
            .windows(SPARK_MODEL_ID.len())
            .any(|w| w == SPARK_MODEL_ID)
}

fn current_has_luna_reserve_for_request(state: &ProxyState, body: &[u8]) -> bool {
    let Some(model) = request_model(body) else {
        return false;
    };
    let Ok(store) = state.store.lock() else {
        return false;
    };
    let Some(current_id) = store.current.as_deref() else {
        return false;
    };
    store
        .accounts
        .get(current_id)
        .and_then(|account| account.cached_quota.as_ref())
        .and_then(|quota| quota.luna_reserve.as_ref())
        .is_some_and(|reserve| reserve.is_available_for(&model))
}

fn current_has_luna_reserve(state: &ProxyState) -> bool {
    let Ok(store) = state.store.lock() else {
        return false;
    };
    let Some(current_id) = store.current.as_deref() else {
        return false;
    };
    store
        .accounts
        .get(current_id)
        .and_then(|account| account.cached_quota.as_ref())
        .and_then(|quota| quota.luna_reserve.as_ref())
        .is_some_and(|reserve| reserve.is_available_for("gpt-5.6-luna"))
}

fn mark_current_luna_reserve_depleted(state: &ProxyState) {
    if let Ok(mut store) = state.store.lock() {
        if let Some(current_id) = store.current.clone() {
            if let Some(account) = store.accounts.get_mut(&current_id) {
                if let Some(reserve) = account
                    .cached_quota
                    .as_mut()
                    .and_then(|quota| quota.luna_reserve.as_mut())
                {
                    reserve.limit_reached = true;
                    reserve.used_percent = 100;
                    let _ = store.save();
                    println!("[Proxy] 当前账号 Luna Reserve 已由上游确认耗尽");
                }
            }
        }
    }
}

/// 429 冷却时长（秒）：撞限额后多久内不再选中该号。10min 足以打断「5min 额度刷新
/// 把 cached 重置 → 立刻又选中 → 又 429」的来回切号；真没额度的号 10min 后再试也无妨。
const QUOTA_COOLDOWN_SECS: i64 = 600;

/// 把某号加入 429 冷却。
fn cooldown_account(state: &ProxyState, account_id: &str) {
    let until = Utc::now().timestamp() + QUOTA_COOLDOWN_SECS;
    if let Ok(mut cd) = state.quota_cooldown.lock() {
        cd.insert(account_id.to_string(), until);
    }
}

/// 该号当前是否在 429 冷却期内（顺便清掉过期项）。
fn is_in_cooldown(state: &ProxyState, account_id: &str) -> bool {
    let now = Utc::now().timestamp();
    if let Ok(mut cd) = state.quota_cooldown.lock() {
        cd.retain(|_, &mut until| until > now);
        return cd.get(account_id).map(|&u| u > now).unwrap_or(false);
    }
    false
}

/// 429 后标记某号 5h 额度耗尽 + 冷却它。
/// 注意：**每个号(每个 seat/登录)是独立额度**——即使同一 chatgpt_account_id(同团队 workspace)
/// 也是各算各的。所以冷却只针对当前这个号，绝不按 account_id 连坐冷却别的 seat。
fn mark_account_quota_depleted(state: &ProxyState, account_id: &str) {
    state.session_affinity.invalidate_account(account_id);
    cooldown_account(state, account_id);
    if let Ok(mut store) = state.store.lock() {
        if let Some(account) = store.accounts.get_mut(account_id) {
            if let Some(ref mut q) = account.cached_quota {
                q.five_hour_left = 0.0;
            }
            let _ = store.save();
        }
    }
}

fn mark_current_quota_depleted(state: &ProxyState) {
    let current_id = match state.store.lock() {
        Ok(s) => s.current.clone(),
        Err(_) => None,
    };
    let Some(current_id) = current_id else {
        return;
    };
    state.session_affinity.invalidate_account(&current_id);
    cooldown_account(state, &current_id);
    if let Ok(mut store) = state.store.lock() {
        if let Some(account) = store.accounts.get_mut(&current_id) {
            if let Some(ref mut q) = account.cached_quota {
                q.five_hour_left = 0.0;
            }
            let _ = store.save();
        }
    }
}

/// 后台拉一次 /wham/usage 把 used_percent 写进 quota-snapshots.jsonl。
/// info 为 None（Relay / 没拿到 access_token / 等）则跳过。
fn spawn_quota_snapshot(
    info: Option<(String, String, Option<String>, Option<String>, String)>,
    trigger: &'static str,
) {
    let (store_id, access_token, chatgpt_account_id, refresh_token, email) = match info {
        Some(x) => x,
        None => return,
    };
    tauri::async_runtime::spawn(async move {
        match crate::usage::UsageFetcher::fetch_usage_direct(
            access_token,
            chatgpt_account_id,
            refresh_token,
            false,
            Some(store_id.to_string()),
        )
        .await
        {
            Ok((usage, _)) => {
                let snap = crate::quota_snapshot::QuotaSnapshot {
                    ts: chrono::Utc::now(),
                    account_id: store_id,
                    email,
                    plan_type: usage.plan_type,
                    five_hour_used_pct: usage.five_hour_used,
                    weekly_used_pct: usage.weekly_used,
                    five_hour_reset_at: usage.five_hour_reset_at,
                    weekly_reset_at: usage.weekly_reset_at,
                    trigger: trigger.to_string(),
                };
                crate::quota_snapshot::append(&snap);
            }
            Err(e) => {
                println!(
                    "[QuotaSnap] {} 抓取失败（trigger={}）: {}",
                    store_id, trigger, e
                );
            }
        }
    });
}

fn do_switch(state: &ProxyState, new_id: &str, reason: SwitchReason) -> Result<(), String> {
    let mut store = state.store.lock().map_err(|e| e.to_string())?;

    // 记录切号前的账号信息
    let from_name = store
        .current
        .as_ref()
        .and_then(|id| store.accounts.get(id))
        .map(|a| a.name.clone());
    let from_quota = store
        .current
        .as_ref()
        .and_then(|id| store.accounts.get(id))
        .and_then(|a| a.cached_quota.as_ref())
        .map(|q| q.five_hour_left);

    // 抓 quota 快照需要的字段（必须在 switch_to 改 store.current 之前取，
    // 否则就拿不到 from 号了）。Relay 号跳过，因为 /wham/usage 不接受其 token。
    let from_fetch_info = store.current.as_ref().and_then(|id| {
        let acc = store.accounts.get(id)?;
        if acc.is_relay() {
            return None;
        }
        let at = crate::account::AccountStore::extract_access_token(&acc.auth_json)?;
        let aid = crate::account::AccountStore::extract_account_id(&acc.auth_json);
        let rt = acc.refresh_token.clone();
        let email = crate::account::AccountStore::extract_email(&acc.auth_json)
            .unwrap_or_else(|| acc.name.clone());
        Some((id.clone(), at, aid, rt, email))
    });
    let to_fetch_info = {
        let acc = store.accounts.get(new_id);
        match acc {
            Some(a) if !a.is_relay() => {
                let at = crate::account::AccountStore::extract_access_token(&a.auth_json);
                let aid = crate::account::AccountStore::extract_account_id(&a.auth_json);
                let rt = a.refresh_token.clone();
                let email = crate::account::AccountStore::extract_email(&a.auth_json)
                    .unwrap_or_else(|| a.name.clone());
                at.map(|at| (new_id.to_string(), at, aid, rt, email))
            }
            _ => None,
        }
    };

    // 代理内部切号：按 switch_mode 决定 hot/cold。proxy 在跑时 hot 完全够 ——
    // 因为 codex（CLI / App 内置二进制）走 OPENAI_BASE_URL=proxy，每次请求 proxy
    // 注入 store.current 的 token，codex 永远拿到 200，不触发 UnauthorizedRecovery。
    // disk auth.json 跟 store 不一致只是"UI 显眼"，不影响 codex 实际工作。
    let hot = crate::account::should_hot_switch(&store.settings, true);
    store.switch_to(new_id, hot)?;
    store.save()?;
    // 切号后远端 token 缓存作废，下一次请求重新拉
    invalidate_remote_token_cache();

    let to_name = store
        .accounts
        .get(new_id)
        .map(|a| a.name.clone())
        .unwrap_or_default();
    let to_quota = store
        .accounts
        .get(new_id)
        .and_then(|a| a.cached_quota.as_ref())
        .map(|q| q.five_hour_left);

    println!("[Proxy] 自动切号 → {} ({})", to_name, reason);

    // 记录切号日志
    state.switch_logger.log_switch(
        from_name.clone(),
        to_name.clone(),
        reason,
        from_quota,
        to_quota,
    );

    state.stats.auto_switches.fetch_add(1, Ordering::Relaxed);
    // 注意：do_switch 这里**不再**广播 ws_disconnect。
    // 理由：notify_waiters 会把所有并发 WS bridge 一口气全炸断（不区分账号），
    // 但实际"该断的"那条 bridge 自己在 detect_ws_rate_limit/banned 里就 send 了
    // Close 帧；其他 bridge 用的是别的号、跟本次切号无关，被殃及只会让 codex
    // 看到 "websocket closed by server before response.completed" + Reconnecting。
    // 手动切号（lib.rs::switch_account）依然 notify，那是用户期望立即生效。
    let _ = state.app_handle.emit("proxy-account-switched", &to_name);
    let _ = state.app_handle.emit("accounts-updated", ());

    // 读取通知设置
    let notify_enabled = store.settings.notify_on_switch;
    let inject_enabled = store.settings.inject_switch_message;
    // solo 模式下把 current 同步给 Server（非阻塞）
    let solo_push = if store.settings.remote_mode == "solo"
        && !store.settings.remote_shared_secret.is_empty()
    {
        Some((
            store.settings.remote_server_url.clone(),
            store.settings.remote_server_url_fallback.clone(),
            store.settings.remote_shared_secret.clone(),
            new_id.to_string(),
        ))
    } else {
        None
    };

    drop(store); // 释放锁

    // Quota 快照：切走前的 from + 切到后的 to，两个时间点的 used_percent 让
    // get_plan_capacity_estimates 能反推 Plan 配额（详见 quota_snapshot.rs）。
    spawn_quota_snapshot(from_fetch_info, "switch_out");
    spawn_quota_snapshot(to_fetch_info, "switch_in");

    if let Some((primary, fallback, secret, nid)) = solo_push {
        tauri::async_runtime::spawn(async move {
            match crate::remote_client::resolve_base_url(&primary, &fallback).await {
                Ok(base) => {
                    // solo 模式：apply_to_disk=false，Server 仅归档 current 不写盘
                    if let Err(e) =
                        crate::remote_client::push_solo_switch(&base, &secret, &nid, false).await
                    {
                        eprintln!("[Solo] 自动切号后 push Server 失败: {}", e);
                    }
                }
                Err(e) => eprintln!("[Solo] Server 不可达，自动切号未同步: {}", e),
            }
        });
    }

    // macOS 系统通知（可配置）
    if cfg!(target_os = "macos") && notify_enabled {
        let from = from_name.unwrap_or_else(|| "无".to_string());
        let notify_msg = format!("{} → {}", from, to_name);
        std::thread::spawn(move || {
            let _ = std::process::Command::new("osascript")
                .arg("-e")
                .arg(format!(
                    "display notification \"{}\" with title \"{}\" subtitle \"{}\"",
                    notify_msg,
                    crate::i18n::APP_NAME,
                    crate::i18n::notification_auto_switch_subtitle()
                ))
                .output();
        });
    }

    // 注入 WebSocket 消息标记（可配置，实验性）
    if inject_enabled {
        PENDING_INJECT_MSG.lock().ok().map(|mut msg| {
            *msg = Some(crate::i18n::injected_switch_message(&to_name));
        });
    }

    Ok(())
}

// ────────────────────────────────────────────────────────────────
// 核心请求处理
// ────────────────────────────────────────────────────────────────

/// Worker 显式声明"这一条请求跟随 current"的标记 header。
///
/// 只认这一个名字、只认值 `1`。**不看 User-Agent、不看模型名** —— Harness、pi
/// sidecar 和 glance 打的是同一个 endpoint，UA 和模型都会漂（Harness 的 UA 由
/// `dsh-llm` 的 attribution 固定，glance 用的是 OpenAI SDK 默认 UA，两边都可能
/// 随版本变），拿它们做判据等于把路由押在一个没人维护的字符串上。
/// 本地专用，`handle_chat_inbound` 自己从零构造出站 header，绝不外泄到 chatgpt.com。
const WORKER_FOLLOW_CURRENT_HEADER: &str = "x-pod-worker-follow-current";

/// `chat/completions` 入站选中的账号来源。决定 401 时怎么处理。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChatInboundPick {
    /// 显式 Worker 标记 → `store.current`。401 只刷新 current 再用 current 重试，
    /// 永不切号、永不去刷别的账号。
    FollowCurrent,
    /// 用户主动定义的硬路由（`session_routes`）。严格模式：401 原样透回。
    HardRoute,
    /// 历史行为：第一个 plan=pro 的非 Relay 账号（glance 的 Spark 通道）。
    SparkPro,
}

/// 请求是否带了 Worker 跟随标记。
///
/// 值必须精确等于 `1`（去掉首尾空白后）。空值、`0`、`true` 都不算 —— 一个模糊
/// 匹配的标记跟按 UA 猜没有本质区别。
fn wants_worker_current(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(WORKER_FOLLOW_CURRENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// `chat/completions` 入站选号的纯决策。
///
/// 抽成纯函数是为了能脱离 `ProxyState` 单测：调用方负责把 store 快照
/// （`current` / `spark_pro`）和硬路由结果喂进来，这里只做优先级判定。
///
/// 优先级：硬路由 > （带标记时）current > pro 扫描。
/// **没带标记时这个函数只可能返回 `SparkPro`**，即 glance 走的还是原来那条路。
fn decide_chat_inbound_pick(
    worker_follow_current: bool,
    hard_routed: Option<&str>,
    current: Option<&str>,
    spark_pro: Option<&str>,
) -> Option<(String, ChatInboundPick)> {
    if worker_follow_current {
        if let Some(id) = hard_routed {
            return Some((id.to_string(), ChatInboundPick::HardRoute));
        }
        if let Some(id) = current {
            return Some((id.to_string(), ChatInboundPick::FollowCurrent));
        }
    }
    spark_pro.map(|id| (id.to_string(), ChatInboundPick::SparkPro))
}

/// 一条 `chat/completions` 入站请求最多允许因 429 切几次号。
///
/// 只有 FollowCurrent 有预算：Worker 明确要求"跟随 current"，切 `store.current`
/// 之后它下一轮自然跟到新号；SparkPro 是 glance 的通道、HardRoute 是用户点名的
/// 账号，替它们换号都会让调用方拿到一个它没要的账号。
///
/// 2 而不是 1：3022 撞限额时池子里有 5 个号，一次只够跳过一个刚耗尽的号。
fn quota_switch_budget(pick: ChatInboundPick) -> u32 {
    match pick {
        ChatInboundPick::FollowCurrent => 2,
        ChatInboundPick::HardRoute | ChatInboundPick::SparkPro => 0,
    }
}

/// OpenAI `chat/completions` 入站处理：翻成 codex `responses`，用一个账号打 ChatGPT
/// 上游，缓冲整条 SSE 后组装回单条 chat/completions JSON。
/// 供 glance 等 OpenAI 兼容客户端复用 ChatGPT 订阅里闲置的 Spark 额度。
///
/// 选号见 `decide_chat_inbound_pick`。Codex CLI/Desktop 到不了这个函数 —— 它走
/// `/v1/responses` + WS，被 `handle_request` 里的 path 守卫挡在外面，全仓库这个
/// 函数只有那一个调用点。
async fn handle_chat_inbound(
    state: Arc<ProxyState>,
    headers_in: &hyper::HeaderMap,
    body: &Bytes,
) -> Response<ProxyBody> {
    let chat: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid JSON: {}", e)),
    };

    // 带 Worker 标记时才查硬路由：`resolve_hard_route` 会写 hit 计数并落盘，
    // 对没带标记的 glance 流量跑它既是行为变化也是无谓写盘。
    let worker_follow_current = wants_worker_current(headers_in);
    let hard_routed: Option<String> = if worker_follow_current {
        resolve_hard_route(&state, body, headers_in).map(|(_sk, aid)| aid)
    } else {
        None
    };

    // 选供号。没带标记 → 只可能落到第一个非 relay 且 plan_type==pro 的账号
    // （Spark 专属），跟这段代码以前的行为逐字相同。
    let (token, name, pick, mut account_id) = {
        let store = match state.store.lock() {
            Ok(s) => s,
            Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        };
        let mut spark_pro: Option<String> = None;
        for (id, acc) in store.accounts.iter() {
            if acc.is_relay() {
                continue;
            }
            let plan = acc
                .cached_quota
                .as_ref()
                .map(|q| q.plan_type.to_lowercase())
                .unwrap_or_default();
            if plan == "pro" && AccountStore::extract_access_token(&acc.auth_json).is_some() {
                spark_pro = Some(id.clone());
                break;
            }
        }
        let decided = decide_chat_inbound_pick(
            worker_follow_current,
            hard_routed.as_deref(),
            store.current.as_deref(),
            spark_pro.as_deref(),
        );
        let Some((account_id, pick)) = decided else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "没有可用的 Pro 账号（chat 入站/Spark 需要一个 plan=pro 的账号；先刷新一次该号配额）",
            );
        };
        // current / 硬路由账号可能缺 access_token（刚导入、被清过），这跟"没有 Pro 号"
        // 不是一回事，报错要分开说，否则运维会去刷一个根本没被选中的账号的配额。
        let Some(acc) = store.accounts.get(&account_id) else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("chat 入站选中的账号不存在: {}", account_id),
            );
        };
        let Some(tok) = AccountStore::extract_access_token(&acc.auth_json) else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("chat 入站选中的账号缺 access_token: {}", acc.name),
            );
        };
        (tok, acc.name.clone(), pick, account_id)
    };

    let want_stream = chat
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let default_model = "gpt-5.3-codex-spark";
    let vision_model = crate::chat_inbound::configured_vision_model();
    let mut responses_body = crate::chat_inbound::chat_to_responses_with_vision_model(
        &chat,
        default_model,
        &vision_model,
    );
    let sid = uuid::Uuid::new_v4().to_string();
    if responses_body.get("prompt_cache_key").is_none() {
        responses_body["prompt_cache_key"] = serde_json::Value::String(sid.clone());
    }
    let model = responses_body
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or(default_model)
        .to_string();
    let pick_label = match pick {
        ChatInboundPick::FollowCurrent => "current(worker)",
        ChatInboundPick::HardRoute => "hard-route(worker)",
        ChatInboundPick::SparkPro => "pro-scan",
    };
    println!(
        "[ChatInbound] 账号={} model={} 选号={}",
        name, model, pick_label
    );

    let body_bytes = match serde_json::to_vec(&responses_body) {
        Ok(v) => Bytes::from(v),
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::HOST,
        reqwest::header::HeaderValue::from_static("chatgpt.com"),
    );
    headers.insert(
        reqwest::header::ACCEPT,
        reqwest::header::HeaderValue::from_static("text/event-stream"),
    );
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static(crate::codex_ua::codex_user_agent()),
    );
    headers.insert(
        reqwest::header::HeaderName::from_static("openai-beta"),
        reqwest::header::HeaderValue::from_static("responses=experimental"),
    );
    headers.insert(
        reqwest::header::HeaderName::from_static("originator"),
        reqwest::header::HeaderValue::from_static(crate::codex_ua::CODEX_ORIGINATOR),
    );
    if let Ok(v) = reqwest::header::HeaderValue::from_str(&sid) {
        headers.insert(reqwest::header::HeaderName::from_static("session_id"), v);
    }

    // spark 偶尔"只 reasoning 不出 message"（空响应）—— 最多重试一次。
    // 这里复用同一个 prompt_cache_key，避免同一入站请求被拆成两个服务端缓存上下文。
    let mut chat_resp = serde_json::Value::Null;
    let mut token = token;
    // 401 静默刷新只允许发生一次，且只在 FollowCurrent 分支：
    // - SparkPro 是扫出来的号，不是 current，刷 current 等于刷错账号；
    // - HardRoute 是用户主动指定的，严格模式下 401 原样透回。
    let mut refresh_left = matches!(pick, ChatInboundPick::FollowCurrent) as u32;
    // 空响应重试跟 401 刷新是两个独立预算。用同一个 `attempt` 计数会让"第二次
    // 尝试撞 401"消耗掉循环的最后一轮，然后带着 chat_resp=Null 掉出循环，把一个
    // 空的 200 当成成功回给客户端。上界仍然收敛：最多 1 次刷新 + 1 次空响应重试。
    let mut empty_retry_left = 1u32;
    // 429 切号预算，只给 FollowCurrent 分支。
    //
    // 这个函数原本对 429 什么都不做：`/v1/responses` 那条路径撞限额会
    // `mark_account_quota_depleted` + `pick_next_account` + `do_switch` 一路换到
    // 健康号，而 chat/completions 入站直接把 429 原样透回。Worker 任务 3022 就
    // 死在这里 —— 四张生活场景图都已通过验收，营销规划撞到 current 的 5h 限额，
    // 整个 attempt 被判为「营销构图方案未通过事实合同」，而池子里另外几个号是好的。
    //
    // 切的是 `store.current` 本身，不是"这一条请求偷偷换个号"：Worker 跟随
    // current，所以下一轮自然也走到新号上，这正是 401 分支注释里担心的
    // "下一轮又打到另一个账号上"的反面。SparkPro 是 glance 的通道，HardRoute 是
    // 用户明确指定的账号，两者都保持原样透回。
    let mut quota_switch_left = quota_switch_budget(pick);
    loop {
        let resp = match forward_with_token(
            &state,
            &hyper::Method::POST,
            &format!("{}/responses", CHATGPT_ORIGIN),
            &headers,
            &body_bytes,
            &token,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                return error_response(StatusCode::BAD_GATEWAY, &format!("上游请求失败: {}", e))
            }
        };
        let status = resp.status();
        let raw = resp.text().await.unwrap_or_default();
        if status.as_u16() == 401 && refresh_left > 0 {
            refresh_left -= 1;
            match silent_refresh_current(&state).await {
                SilentRefreshOutcome::Refreshed(fresh) => {
                    println!("[ChatInbound] current 401，静默刷新成功，用 current 重试");
                    token = fresh;
                    continue;
                }
                other => {
                    let why = match other {
                        SilentRefreshOutcome::LoggedOut => "current 已登出".to_string(),
                        SilentRefreshOutcome::NoRefreshToken => {
                            "current 没有 refresh_token".to_string()
                        }
                        SilentRefreshOutcome::OtherError(e) => e,
                        SilentRefreshOutcome::Refreshed(_) => unreachable!(),
                    };
                    // 刷不动就把上游 401 原样透回。这里刻意不切号 —— Worker 要的是
                    // "跟随 current"，悄悄换一个号会让下一轮又打到另一个账号上。
                    eprintln!("[ChatInbound] current 401 且刷新失败：{}", why);
                }
            }
        }
        if status.as_u16() == 429 && quota_switch_left > 0 {
            quota_switch_left -= 1;
            // 先把这个号标成 5h 耗尽并冷却，否则 pick_next_account 可能立刻又选中它。
            mark_account_quota_depleted(&state, &account_id);
            match pick_next_account(&state) {
                PickResult::Found { id, token: next } => {
                    match do_switch(&state, &id, SwitchReason::Http429) {
                        Ok(()) => {
                            println!(
                                "[ChatInbound] current 429（{}），已切到账号 {} 并重试",
                                name, id
                            );
                            token = next;
                            account_id = id;
                            continue;
                        }
                        Err(e) => {
                            eprintln!("[ChatInbound] 429 切号失败：{}", e);
                        }
                    }
                }
                PickResult::Exhausted { earliest_reset } => {
                    eprintln!(
                        "[ChatInbound] current 429 且账号池已全部耗尽，最早恢复：{:?}",
                        earliest_reset
                    );
                }
            }
            // 切不动就落到下面把上游 429 原样透回。
        }
        if !status.is_success() {
            let msg = crate::chat_inbound::extract_upstream_error(&raw)
                .unwrap_or_else(|| format!("上游 HTTP {}", status.as_u16()));
            return error_response(
                StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
                &msg,
            );
        }
        let parsed = crate::chat_inbound::responses_sse_to_chat(&raw, &model);
        // 有内容或有 tool_calls 就用它；否则（空响应）再试一次
        let msg = &parsed["choices"][0]["message"];
        let has_content = msg.get("content").map(|c| !c.is_null()).unwrap_or(false);
        let has_tools = msg.get("tool_calls").map(|t| t.is_array()).unwrap_or(false);
        chat_resp = parsed;
        if has_content || has_tools || empty_retry_left == 0 {
            break;
        }
        empty_retry_left -= 1;
        println!("[ChatInbound] 空响应，重试一次");
    }

    if want_stream {
        // stream=true：回 Chat Completions SSE，否则只认 SSE delta 的客户端（hermes）
        // 拿到普通 JSON 解析不出内容 → content=None → 空响应误判。
        let sse = crate::chat_inbound::chat_completion_to_sse(&chat_resp);
        Response::builder()
            .status(200)
            .header("content-type", "text/event-stream")
            .header("cache-control", "no-cache")
            .body(full_body(Bytes::from(sse)))
            .unwrap()
    } else {
        Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(full_body(Bytes::from(chat_resp.to_string())))
            .unwrap()
    }
}

async fn handle_request(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
) -> Result<Response<ProxyBody>, Infallible> {
    state.stats.total_requests.fetch_add(1, Ordering::Relaxed);

    // ── 健康检查 ──
    if req.method() == Method::GET && req.uri().path() == "/health" {
        let total = state.stats.total_requests.load(Ordering::Relaxed);
        let switches = state.stats.auto_switches.load(Ordering::Relaxed);
        let body = serde_json::json!({
            "status": "ok",
            "total_requests": total,
            "auto_switches": switches,
        });
        return Ok(Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(full_body(Bytes::from(body.to_string())))
            .unwrap());
    }

    // 已连接 Google 账号时，将 Antigravity 模型合并进 Codex 原生模型目录。
    // Client 只需无密钥账号镜像即可展示；推理本机直出，ST 向 Mini 租用。
    if req.method() == Method::GET
        && (req.uri().path() == "/v1/models" || req.uri().path().ends_with("/models"))
    {
        if has_antigravity_account(&state) || has_named_relay_models(&state) {
            let headers = req.headers().clone();
            let path_and_query = req
                .uri()
                .path_and_query()
                .map(|value| value.as_str().to_string())
                .unwrap_or_else(|| "/v1/models".to_string());
            return Ok(handle_models_with_antigravity(state, &headers, &path_and_query).await);
        }
    }

    // ── WebSocket 升级检测 ──
    if is_websocket_upgrade(&req) {
        // DEBUG: dump 所有 upgrade headers，找 session_id 藏在哪
        {
            let dump_all = std::env::var("PROXY_DEBUG_ALL_HEADERS").is_ok();
            println!("[Proxy DEBUG] WS upgrade headers:");
            for (name, value) in req.headers() {
                let lower = name.as_str().to_lowercase();
                let v = if lower == "authorization" {
                    "(redacted)"
                } else {
                    value.to_str().unwrap_or("(non-ascii)")
                };
                // 默认只 print session 相关的，避免日志爆；设
                // PROXY_DEBUG_ALL_HEADERS=1 时打印真实客户端发的全部 header，
                // 用来核对官方 codex 的完整 header 集合。
                if dump_all
                    || lower.contains("session")
                    || lower.contains("codex")
                    || lower.contains("turn")
                    || lower.contains("originator")
                    || lower.contains("thread")
                    || lower.contains("conversation")
                    || lower.contains("trace")
                    || lower.contains("agent")
                {
                    println!("[Proxy DEBUG]   {}: {}", name, v);
                }
            }
        }
        // Desktop provides the selected model in a local routing hint. Route
        // provider models before opening any ChatGPT socket; the old late probe
        // added an avoidable handshake and could strand the first turn.
        if routing_hint_model(req.headers())
            .as_deref()
            .is_some_and(|model| {
                antigravity_model_available(&state, model)
                    || crate::relay_catalog::is_relay_model_slug(model)
            })
        {
            return handle_model_routed_websocket(state, req).await;
        }
        // Hard route 优先：WS upgrade body 是空的，只查 headers（codex 用
        // session_id / x-session-id / Session_id header 透 session_key 出来）。
        if let Some((_sk, account_id)) = resolve_hard_route(&state, &[], req.headers()) {
            if let Some(hard_relay) = relay_route_for_account(&state, &account_id) {
                if hard_relay.protocol == "chat_completions" {
                    println!(
                        "[Proxy] Hard route WS → chat_completions Relay 适配器（{}）",
                        hard_relay.account_id
                    );
                    return handle_chat_completions_relay_websocket(state, hard_relay, req).await;
                }
                // 绑定的 Relay 是 responses 协议 —— 当成普通 WS 直接进 handle_websocket，
                // 但需要把 store.current 临时改成绑定账号。WS 路径目前不支持 per-request
                // 账号覆盖，暂不实现该分支（用户应该选 chat_completions 协议的 Relay 才 ok）。
                println!(
                    "[Proxy] Hard route 绑定的 Relay 是 responses 协议，WS 路径暂不支持 per-request 覆盖，落回 current"
                );
            }
            // 绑定的不是 Relay（订阅号），WS 路径要做 per-request 账号覆盖很复杂。
            // 当前限制：hard route 在 WS 路径只对 chat_completions Relay 生效。
        }

        if let Some(relay) = current_relay_route(&state) {
            if relay.protocol == "chat_completions" {
                println!(
                    "[Proxy] WebSocket upgrade 转入 chat_completions Relay 适配器：{}",
                    req.uri()
                );
                return handle_chat_completions_relay_websocket(state, relay, req).await;
            }
            if relay.protocol == "responses" {
                // Most Responses relays expose HTTP/SSE only. Reuse the local
                // Responses bridge instead of assuming the relay also accepts
                // a native WebSocket handshake.
                println!(
                    "[Proxy] Responses Relay WS → local HTTP/SSE bridge: {}",
                    req.uri()
                );
                return handle_model_routed_websocket(state, req).await;
            }
        }
        println!("[Proxy] WebSocket upgrade 请求: {}", req.uri());
        return handle_websocket(state, req).await;
    }

    // ── 读取请求元数据 + body（client/server 分支共用）──
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let req_headers = req.headers().clone();
    let body_bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            eprintln!("[Proxy] 读取请求体失败: {}", e);
            return Ok(error_response(StatusCode::BAD_REQUEST, "读取请求体失败"));
        }
    };

    // ── 原生 Antigravity 模型路由 ──
    // Client 与 Codex 同构：Mini 只管 RT/ST，请求从当前运行 Codex 的机器直连 Google。
    let body_for_routing = match decode_request_body_for_routing(&req_headers, &body_bytes) {
        Ok(body) => body,
        Err(error) => return Ok(error_response(StatusCode::BAD_REQUEST, &error)),
    };
    if let Some(model) = request_model(&body_for_routing) {
        if crate::relay_catalog::is_relay_model_slug(&model) {
            return Ok(handle_named_relay_response(
                state,
                method,
                &path_and_query,
                req_headers,
                body_for_routing,
                &model,
            )
            .await);
        }
        if antigravity_model_available(&state, &model) {
            return Ok(handle_antigravity_response(
                state,
                method,
                &path_and_query,
                body_for_routing,
            )
            .await);
        }
    }

    // ── OpenAI chat/completions 入站（glance 等 OpenAI 兼容客户端用 ChatGPT 账号的 codex 模型）──
    // 与下面 responses 路径完全独立：chat → 翻成 codex responses → 打 ChatGPT 上游 → 缓冲 SSE
    // → 组装回单条 chat/completions JSON。详见 chat_inbound 模块。
    {
        let p = path_and_query.split('?').next().unwrap_or("");
        if method == Method::POST && (p == "/v1/chat/completions" || p == "/chat/completions") {
            return Ok(handle_chat_inbound(state, &req_headers, &body_bytes).await);
        }
    }

    // ── Relay 路由前置处理 ──
    // 1) Hard route 优先覆盖 current；2) 当有效 Relay 存在时重写 body 里的
    // `model` 字段（codex 端发的 gpt-* → 上游实际模型）；3) Relay 不能走
    // client→Server 转发，必须在 token 解析前锁定它自己的 API key/base_url。
    let relay_route = current_relay_route(&state);
    let hard_route_relay: Option<RelayRoute> =
        resolve_hard_route(&state, &body_bytes, &req_headers)
            .and_then(|(_sk, aid)| relay_route_for_account(&state, &aid));
    let effective_relay = hard_route_relay.as_ref().or(relay_route.as_ref());
    let body_bytes = if let Some(r) = effective_relay {
        rewrite_model_in_body(
            &body_bytes,
            r.model_map.as_ref(),
            r.model_fallback.as_deref(),
        )
    } else {
        body_bytes
    };

    // ── chat_completions Relay 翻译分支 ──
    // Relay 上游只懂 /chat/completions（GLM Coding Plan / MiMo 等）→ 用 relay_translate 把
    // codex 的 /v1/responses 翻译成 chat 协议，调好上游再把响应（SSE 或 sync）反翻译回来。
    // 优先用 hard_route_relay（用户显式指定的路由）；否则用 current_relay_route。
    if let Some(r) = effective_relay {
        if r.protocol == "chat_completions" {
            return Ok(handle_chat_completions_relay(
                state.clone(),
                r.clone(),
                method.clone(),
                path_and_query.clone(),
                req_headers.clone(),
                body_bytes.clone(),
            )
            .await);
        }
    }

    // 提取 session_key：用于 affinity 路由 + cache hit 记账（client 模式 affinity 由 Server 处理）
    let session_key = crate::session_affinity::extract_session_key(&body_bytes, &req_headers);

    // ── client 模式：先转发到 Server；Server 不可达或返回 402 deactivated 时回退本地 ──
    // 注意：Relay 账号不再走 Server。Relay 用 API key 直连上游，没有账号池/保活/401-切号
    // 那套需求，多一跳 LAN 纯加延迟。让 Relay 在 client 机器本地直接打上游
    // （chat_completions 协议已在更上游分支返回；responses 协议落到下面 get_upstream
    // 直发 unity2/packycode）。
    let (remote_mode, client_direct_upstream) = state
        .store
        .lock()
        .map(|s| {
            (
                s.settings.remote_mode.clone(),
                s.settings.client_direct_upstream,
            )
        })
        .unwrap_or((String::new(), false));

    // client_direct_upstream=true：HTTP 也走"本机直连上游"（跟 WS 同路）；
    // 只让 Server 管 RT/AT 轮换。跳过 forward_to_server 这一段，直接 fall through
    // 到下面的本地路径（resolve_token_with_affinity → forward_with_token）。
    // resolve_token_with_affinity 在 client 模式下会自动从 Server fetch_token，
    // 所以 token 中心化的语义保留。
    if remote_mode == "client" && effective_relay.is_none() && !client_direct_upstream {
        // 先尝试 silent retry：peek 响应首 chunk，撞 usage_limit_reached 就切号重试，最多 3 次
        match forward_to_server_with_silent_retry(
            &state,
            &method,
            &path_and_query,
            &req_headers,
            &body_bytes,
            3,
        )
        .await
        {
            Ok(Some(resp)) => return Ok(resp),
            Ok(None) => {
                // 402 deactivated：走老路径，重新 forward 一次拿 body 检查
                match forward_to_server_parts(
                    &state,
                    &method,
                    &path_and_query,
                    &req_headers,
                    &body_bytes,
                )
                .await
                {
                    Ok(mini_resp) => {
                        let resp_bytes = mini_resp.bytes().await.unwrap_or_default();
                        let lower = String::from_utf8_lossy(&resp_bytes).to_lowercase();
                        let is_deactivated = lower.contains("deactivated")
                            || lower.contains("account_deactivated")
                            || lower.contains("deactivated_workspace");
                        if is_deactivated {
                            println!("[Proxy] Server 返回 402 deactivated，尝试本地账号回退");
                            if let Some(resp) = try_local_fallback(
                                &state,
                                &method,
                                &path_and_query,
                                &req_headers,
                                &body_bytes,
                                session_key.as_deref(),
                            )
                            .await
                            {
                                return Ok(resp);
                            }
                        }
                        return Ok(Response::builder()
                            .status(402)
                            .header("content-type", "application/json")
                            .body(full_body(resp_bytes))
                            .unwrap_or_else(|_| {
                                error_response(StatusCode::PAYMENT_REQUIRED, "402")
                            }));
                    }
                    Err(e) => {
                        eprintln!("[Proxy] 402 二次取 body 失败: {}", e);
                        // 落到下面 fall-through
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "[Proxy] Server 转发失败（{}），fall through 到本地完整 401/429 处理路径",
                    e
                );
                // 不再 early-return：让执行流走到下面非 client 模式的完整逻辑去
                // （含 silent_refresh + try_switch_and_retry + SSE bootstrap）
                // 这样即使 Server 不可达，本机用 store.current 的 token 直连上游被 401 时，
                // 也会自动 refresh / 切号，而不是把 401 透回给 codex。
            }
        }
    }

    // 1. 获取认证信息：native Responses Relay 必须锁定 Relay 自己的 API key，
    // 不能让本地 HTTP/SSE bridge 回落到官方 OAuth token。chat_completions Relay
    // 已在上面的适配分支返回；其余请求才走账号池/affinity。
    // hard_routed=true 表示命中用户主动定义的 session_routes（严格模式：不要切号/refresh）。
    let (token, is_chatgpt, used_account_id, hard_routed) =
        if let Some(relay) = effective_relay.filter(|r| r.protocol == "responses") {
            let token = relay
                .api_key
                .clone()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| "Responses Relay 缺少 API key".to_string());
            match token {
                Ok(token) => {
                    println!(
                        "[Proxy] native Responses Relay → {} {} (account={})",
                        method, path_and_query, relay.account_id
                    );
                    (
                        token,
                        false,
                        Some(relay.account_id.clone()),
                        hard_route_relay.is_some(),
                    )
                }
                Err(error) => return Ok(error_response(StatusCode::SERVICE_UNAVAILABLE, &error)),
            }
        } else {
            match resolve_token_with_affinity(&state, session_key.as_deref()).await {
                Ok(t) => t,
                Err(e) => return Ok(error_response(StatusCode::SERVICE_UNAVAILABLE, &e)),
            }
        };
    let body_bytes = if is_chatgpt {
        normalize_chatgpt_responses_body(&body_bytes, &path_and_query, &req_headers)
    } else {
        body_bytes
    };
    let session_affinity_ctx = match (session_key.clone(), used_account_id.clone()) {
        (Some(sk), Some(aid)) => Some(AffinityCtx {
            affinity: state.session_affinity.clone(),
            session_key: sk,
            account_id: aid,
        }),
        _ => None,
    };

    // 2. 根据认证模式路由上游（Relay 类型从 used_account_id 查 base_url）
    let relay_base_url = used_account_id
        .as_deref()
        .and_then(|id| account_relay_base_url(&state, id));
    let (upstream_url, upstream_host) =
        get_upstream(is_chatgpt, relay_base_url.as_deref(), &path_and_query);

    // 3. 透明 Header 转发（官方 responses-api-proxy 逻辑）
    if is_chatgpt && std::env::var("PROXY_DEBUG_ALL_HEADERS").is_ok() {
        println!(
            "[Proxy DEBUG] HTTP POST {} inbound headers:",
            path_and_query
        );
        for (name, value) in &req_headers {
            let lower = name.as_str().to_lowercase();
            let v = if lower == "authorization" {
                "(redacted)"
            } else {
                value.to_str().unwrap_or("(non-ascii)")
            };
            println!("[Proxy DEBUG]   {}: {}", name, v);
        }
    }
    let base_headers = build_upstream_headers(&req_headers, &upstream_host);

    // 5. 首次转发
    let upstream_resp = match forward_with_token(
        &state,
        &method,
        &upstream_url,
        &base_headers,
        &body_bytes,
        &token,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("上游连接失败: {}", e),
            ))
        }
    };

    let status_code = upstream_resp.status();

    // 6. 封号检测（401/402/403）
    //    - 401/403 可能是 token 过期、登出、或封号；body 里有 deactivated 关键词视为封号
    //    - 402 Payment Required（deactivated_workspace）始终视为封号
    if status_code == reqwest::StatusCode::UNAUTHORIZED
        || status_code == reqwest::StatusCode::FORBIDDEN
        || status_code == reqwest::StatusCode::PAYMENT_REQUIRED
    {
        // 严格模式：硬路由命中时，401/402/403 一律原样透回，不切号、不 silent_refresh、
        // 也不标记账号。用户主动指定了这个号，他需要看到上游真实错误来决定是否重登/解禁。
        if hard_routed {
            let resp_bytes = upstream_resp.bytes().await.unwrap_or_default();
            println!(
                "[Proxy] Hard route 严格模式：上游 {} 原样透回，不触发切号",
                status_code
            );
            return Ok(Response::builder()
                .status(status_code.as_u16())
                .header("content-type", "application/json")
                .body(full_body(resp_bytes))
                .unwrap_or_else(|_| error_response(StatusCode::BAD_GATEWAY, "响应构建失败")));
        }
        // 记下触发错误的账号名（在 silent_refresh / 切号污染 store.current 之前）
        let triggering_account_name: String = state
            .store
            .lock()
            .ok()
            .and_then(|s| {
                let id = s.current.clone()?;
                s.accounts.get(&id).map(|a| a.name.clone())
            })
            .unwrap_or_else(|| "未知".to_string());

        let resp_bytes = upstream_resp.bytes().await.unwrap_or_default();
        let body_lower = String::from_utf8_lossy(&resp_bytes).to_lowercase();
        let body_hits_banned = body_lower.contains("deactivated")
            || body_lower.contains("banned")
            || body_lower.contains("suspended")
            || body_lower.contains("account_deactivated")
            || body_lower.contains("deactivated_workspace");
        let is_402 = status_code == reqwest::StatusCode::PAYMENT_REQUIRED;
        let banned = body_hits_banned || is_402;

        if banned {
            println!(
                "[Proxy] 封号检测触发（status={}），标记并切号...",
                status_code
            );
            mark_current_banned(&state);

            if let Some(resp) = try_switch_and_retry(
                &state,
                &method,
                &upstream_url,
                &base_headers,
                &body_bytes,
                session_key.as_deref(),
                SwitchReason::BannedDetected,
            )
            .await
            {
                return Ok(resp);
            }
        } else {
            // current 是 Relay 时跳过 silent_refresh —— Relay 账号用静态 API Key，
            // 没有 refresh_token 也不会被轮换/过期。401 几乎只可能是上游 hiccup 或
            // key 被用户手动 revoke。silent_refresh 跑下来必返 NoRefreshToken，
            // 旧逻辑会把账号永久标 is_token_invalid → UI 显示"过期" → 用户困惑。
            let current_is_relay = state
                .store
                .lock()
                .ok()
                .and_then(|s| {
                    let id = s.current.clone()?;
                    s.accounts.get(&id).map(|a| a.is_relay())
                })
                .unwrap_or(false);
            if current_is_relay {
                println!("[Proxy] 拦截到 401（Relay 账号），跳过 silent_refresh 直接试切号");
                if let Some(resp) = try_switch_and_retry(
                    &state,
                    &method,
                    &upstream_url,
                    &base_headers,
                    &body_bytes,
                    session_key.as_deref(),
                    SwitchReason::Http429,
                )
                .await
                {
                    return Ok(resp);
                }
                // 切号无果 → 把原 401 body 透回（用户能看到上游的真实错误信息）
                return Ok(Response::builder()
                    .status(status_code.as_u16())
                    .header("content-type", "application/json")
                    .body(full_body(resp_bytes))
                    .unwrap_or_else(|_| error_response(StatusCode::BAD_GATEWAY, "响应构建失败")));
            }
            // 非 Relay：401 可能是正常过期或被登出。
            // 按设计：client / solo 模式下 Server 是 RT 轮换的唯一权威，本机不独自 refresh
            // —— 优先问 Server 拿 fresh token，避免和 Server 撞轮换；Server 不可达再降级本地。
            // off / server 模式下本地直接 refresh。
            println!("[Proxy] 拦截到 401，尝试刷新 Token...");

            let outcome = silent_refresh_current(&state).await;
            match outcome {
                SilentRefreshOutcome::Refreshed(new_token) => {
                    if let Ok(retry_resp) = forward_with_token(
                        &state,
                        &method,
                        &upstream_url,
                        &base_headers,
                        &body_bytes,
                        &new_token,
                    )
                    .await
                    {
                        return Ok(build_stream_response(
                            retry_resp,
                            Some(state.tracker.clone()),
                            session_affinity_ctx.clone(),
                        ));
                    }
                }
                SilentRefreshOutcome::LoggedOut
                | SilentRefreshOutcome::OtherError(_)
                | SilentRefreshOutcome::NoRefreshToken => {
                    // 只有"明确的 auth 信号"才持久标记失效（铁律：网络层/容量/auth 抖动一律不标）：
                    //   LoggedOut      = OAuth 端点明确 invalid_grant / 登出 → is_logged_out
                    //   NoRefreshToken = 根本没 refresh_token，无法恢复     → is_token_invalid
                    //   OtherError     = 网络抖动 / 429 / 5xx / 连不上 auth.openai.com（Server 经
                    //                    192.168.2.250→38 出口，抖动是常态）→ 瞬时，绝不标记失效，
                    //                    只切号让本次请求走通，账号状态保持原样（否则好号被误判"过期"）
                    let mark_field: Option<&str> = match &outcome {
                        SilentRefreshOutcome::LoggedOut => Some("logged_out"),
                        SilentRefreshOutcome::NoRefreshToken => Some("token_invalid"),
                        SilentRefreshOutcome::OtherError(_) => None,
                        _ => unreachable!(),
                    };
                    let log_tag = match &outcome {
                        SilentRefreshOutcome::LoggedOut => "账号已登出/RT 被轮换".to_string(),
                        SilentRefreshOutcome::NoRefreshToken => {
                            "缺 refresh_token 无法刷新".to_string()
                        }
                        SilentRefreshOutcome::OtherError(e) => format!("瞬时刷新失败: {}", e),
                        _ => unreachable!(),
                    };
                    if let Some(field) = mark_field {
                        println!(
                            "[Proxy] silent_refresh 不可恢复（{}），标记 + 切号",
                            log_tag
                        );
                        if let Ok(mut store) = state.store.lock() {
                            if let Some(current_id) = store.current.clone() {
                                if let Some(acc) = store.accounts.get_mut(&current_id) {
                                    if field == "logged_out" {
                                        acc.is_logged_out = true;
                                    } else {
                                        acc.is_token_invalid = true;
                                    }
                                    let _ = store.save();
                                }
                            }
                        }
                    } else {
                        println!(
                            "[Proxy] silent_refresh 瞬时失败（{}），不标记失效，仅切号重试",
                            log_tag
                        );
                    }
                    if let Some(resp) = try_switch_and_retry(
                        &state,
                        &method,
                        &upstream_url,
                        &base_headers,
                        &body_bytes,
                        session_key.as_deref(),
                        SwitchReason::Http429,
                    )
                    .await
                    {
                        return Ok(resp);
                    }
                }
            }
        }

        // 所有切号尝试都失败 / 账号池耗尽。
        // **不要把上游原始 401 body 透回 codex**（典型文案：
        //   "Your access token could not be refreshed because you have since
        //    logged out or signed in to another account."），用户看了一头雾水、
        //   不知道是哪个号、也不知道是切号链失败还是 codex 自己出问题。
        // 改成清楚的中文+英文错误，包含触发账号名，方便对照排查。
        let friendly = serde_json::json!({
            "error": {
                "type": "invalid_request_error",
                "code": "all_accounts_exhausted",
                "message": format!(
                    "[Codex Switcher] 触发账号「{}」失效或限额，自动切号链已经试过所有可用号都失败 / 已耗尽。请打开 Codex Switcher 检查账号面板：刷新配额、重新登录失效的号、或者手动切到健康的订阅号。原上游响应已存日志。 / Triggering account \"{}\" failed; auto-switch chain exhausted all candidates.",
                    triggering_account_name, triggering_account_name
                ),
                "param": null,
            }
        });
        let body_bytes = serde_json::to_vec(&friendly).unwrap_or(resp_bytes.to_vec());
        eprintln!(
            "[Proxy] 401/403 链路完全失败，原始上游 body 前 200 字符: {}",
            String::from_utf8_lossy(&resp_bytes)
                .chars()
                .take(200)
                .collect::<String>()
        );
        let _ = state.app_handle.emit(
            "proxy-account-failed",
            &format!(
                "账号「{}」401/限额耗尽，切号链失败",
                triggering_account_name
            ),
        );
        return Ok(Response::builder()
            .status(status_code.as_u16())
            .header("content-type", "application/json")
            .body(full_body(Bytes::from(body_bytes)))
            .unwrap_or_else(|_| error_response(StatusCode::BAD_GATEWAY, "响应构建失败")));
    }

    // 7. HTTP 429：按 body 内容分流
    //   - body 含 server_is_overloaded / slow_down → **全局过载**，同号 backoff retry
    //     （切号撞同样错，烧账号没用）
    //   - body 含 usage_limit_reached / insufficient_quota / usage_not_included
    //     → per-account 配额耗尽，切号
    //   - 其他 429（无明确 code） → 默认切号
    //
    // `/responses/compact` 特殊处理：
    // 验证 codex 源码（codex-rs/codex-api/src/common.rs CompactionInput）后确认，
    // compact 请求体 **不带 response_id**，body 是 `input: Vec<ResponseItem>`（完整
    // 对话历史）+ 标准参数；headers 也明确传 `turn_state=None`。所以切到新号重试在
    // 协议层是合法的 —— 之前 0.5.14 关闭切号是基于"response_id 绑死账号"的错误假设。
    //
    // 这里改成：先乐观切号重试。
    //   - 重试拿到 2xx → 真无损切号，codex 不感知错误
    //   - 重试拿到 4xx（仍有别的服务端绑定如 session_id / 信任度问题）→ **不把 4xx 透回**
    //     codex（4xx 是 terminal，整条对话就死了），改成把原始 429 透回（transient，codex
    //     只是放弃这次 compact，session 继续工作）
    let is_compact_path = path_and_query.contains("/responses/compact");
    if status_code == reqwest::StatusCode::TOO_MANY_REQUESTS && is_compact_path {
        let resp_bytes = upstream_resp.bytes().await.unwrap_or_default();
        if hard_routed {
            println!("[Proxy] Hard route 严格模式：compact 429 原样透回");
            return Ok(Response::builder()
                .status(429)
                .header("content-type", "application/json")
                .body(full_body(resp_bytes))
                .unwrap_or_else(|_| error_response(StatusCode::TOO_MANY_REQUESTS, "429")));
        }
        println!("[Proxy] compact 路径 429，尝试切号重试（最多 5 个号）...");
        mark_current_quota_depleted(&state);
        const COMPACT_MAX_SWITCH_ATTEMPTS: usize = 5;
        for attempt in 0..COMPACT_MAX_SWITCH_ATTEMPTS {
            let Some(retry_resp) = dispatch_quota_switch_retry(
                &state,
                &method,
                &upstream_url,
                &base_headers,
                &body_bytes,
                session_key.as_deref(),
                SwitchReason::Http429,
            )
            .await
            else {
                println!(
                    "[Proxy] compact 第 {}/{} 次切号无候选可选，停止",
                    attempt + 1,
                    COMPACT_MAX_SWITCH_ATTEMPTS
                );
                break;
            };

            let retry_status = retry_resp.status();
            if retry_status.is_success() {
                println!(
                    "[Proxy] compact 切号重试成功（{}），第 {} 次无损切号",
                    retry_status,
                    attempt + 1
                );
                return Ok(retry_resp);
            }

            // 把 4xx body 缓出来留作 log + 判断要不要再切
            let retry_headers = retry_resp.headers().clone();
            let retry_body = match retry_resp.into_body().collect().await {
                Ok(c) => c.to_bytes(),
                Err(e) => {
                    eprintln!("[Proxy] compact 重试 body 读取失败: {}", e);
                    Bytes::new()
                }
            };
            let preview: String = String::from_utf8_lossy(&retry_body)
                .chars()
                .take(400)
                .collect();
            println!(
                "[Proxy] compact 第 {} 次切号返 {} body[0:400]={:?}",
                attempt + 1,
                retry_status,
                preview
            );

            // 4xx 类账号特异性失败（plan 不够、session 绑定等）→ 当前账号也标耗尽，
            // 让 dispatch_quota_switch_retry 下一轮请求 Server 换不同的号
            if retry_status.is_client_error() {
                mark_current_quota_depleted(&state);
                if attempt + 1 < COMPACT_MAX_SWITCH_ATTEMPTS {
                    println!(
                        "[Proxy] compact 4xx 视为该号不可用，继续试下一个号 ({}/{})",
                        attempt + 2,
                        COMPACT_MAX_SWITCH_ATTEMPTS
                    );
                    continue;
                }
                // 全部用完仍 4xx → 伪装 429 给 codex（避免 4xx 触发 codex 终端崩）
                println!(
                    "[Proxy] compact 试完 {} 个号仍 4xx，伪装 429 透回（最后一次 status={}）",
                    COMPACT_MAX_SWITCH_ATTEMPTS, retry_status
                );
                break;
            }

            // 5xx 类（服务端临时） → 也透回 4xx body 让 codex 自己决定（已经能透回非 4xx）
            println!(
                "[Proxy] compact 切号后返 {} 5xx 类，透回原响应",
                retry_status
            );
            let mut builder = Response::builder().status(retry_status);
            for (k, v) in retry_headers.iter() {
                builder = builder.header(k, v);
            }
            return Ok(builder
                .body(full_body(retry_body))
                .unwrap_or_else(|_| error_response(retry_status, "5xx")));
        }
        return Ok(Response::builder()
            .status(429)
            .header("content-type", "application/json")
            .body(full_body(resp_bytes))
            .unwrap_or_else(|_| error_response(StatusCode::TOO_MANY_REQUESTS, "429")));
    }
    if status_code == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let resp_bytes = upstream_resp.bytes().await.unwrap_or_default();
        if hard_routed {
            println!("[Proxy] Hard route 严格模式：429 原样透回");
            return Ok(Response::builder()
                .status(429)
                .header("content-type", "application/json")
                .body(full_body(resp_bytes))
                .unwrap_or_else(|_| error_response(StatusCode::TOO_MANY_REQUESTS, "429")));
        }
        // Spark 模型 429 = Pro 专属子限额耗尽，与基础额度无关：**不切号、不标耗尽**，
        // 原样把 429 透回给 Spark 调用方（glance/hermes）。否则会把当前账号误判成没额度
        // 切走，连带把同账号上正常的 gpt-5.5 会话踢到没额度的号 → 任务停。
        if request_is_spark_model(&body_bytes) {
            println!("[Proxy] Spark 模型 429（Pro 子限额耗尽），不切号，原样透回 429");
            return Ok(Response::builder()
                .status(429)
                .header("content-type", "application/json")
                .body(full_body(resp_bytes))
                .unwrap_or_else(|_| error_response(StatusCode::TOO_MANY_REQUESTS, "429")));
        }
        if current_has_luna_reserve_for_request(&state, &body_bytes) {
            println!("[Proxy] Luna Reserve 可用，429 不切号，仅关闭本次请求");
            return Ok(Response::builder()
                .status(429)
                .header("content-type", "application/json")
                .body(full_body(resp_bytes))
                .unwrap_or_else(|_| error_response(StatusCode::TOO_MANY_REQUESTS, "429")));
        }
        let body_lower = String::from_utf8_lossy(&resp_bytes).to_lowercase();
        let is_capacity = body_lower.contains("server_is_overloaded")
            || body_lower.contains("slow_down")
            || matches_global_capacity(&body_lower);

        if is_capacity {
            println!("[Proxy] HTTP 429 + body 含 capacity 关键词，同号 backoff retry...");
            // 同号 backoff retry 3 次（复用与 step 7.5 同样的逻辑思路）
            for attempt in 1..=3u64 {
                let backoff = std::time::Duration::from_secs(2 * attempt);
                tokio::time::sleep(backoff).await;
                let (retry_token, _) =
                    match resolve_token_with_affinity(&state, session_key.as_deref()).await {
                        Ok((t, c, _, _)) => (t, c),
                        Err(_) => continue,
                    };
                if let Ok(retry_resp) = forward_with_token(
                    &state,
                    &method,
                    &upstream_url,
                    &base_headers,
                    &body_bytes,
                    &retry_token,
                )
                .await
                {
                    let s = retry_resp.status();
                    if s == reqwest::StatusCode::OK {
                        println!("[Proxy] 429 capacity 同号 retry 第 {} 次成功", attempt);
                        if is_sse_response(&retry_resp) {
                            let h = retry_resp.headers().clone();
                            let stream = retry_resp.bytes_stream().boxed();
                            let resp = build_streaming_response_with_bootstrap(
                                state.clone(),
                                s,
                                h,
                                stream,
                                method.clone(),
                                upstream_url.clone(),
                                base_headers.clone(),
                                body_bytes.clone(),
                                session_affinity_ctx.clone(),
                            );
                            return Ok(resp);
                        }
                        return Ok(build_stream_response(
                            retry_resp,
                            Some(state.tracker.clone()),
                            session_affinity_ctx.clone(),
                        ));
                    }
                    if s == reqwest::StatusCode::TOO_MANY_REQUESTS
                        || (s.as_u16() >= 500 && s.as_u16() < 600)
                    {
                        continue;
                    }
                    return Ok(build_stream_response(
                        retry_resp,
                        Some(state.tracker.clone()),
                        session_affinity_ctx.clone(),
                    ));
                }
            }
            println!("[Proxy] 429 capacity 同号 retry 三次都失败，降级走切号兜底");
            // 撑不住 → 切号兜底
        }

        // 走切号路径（per-account 限额 OR capacity 同号 retry 失败兜底）
        if !is_capacity {
            println!("[Proxy] HTTP 429 (per-account 限额)，标记额度耗尽并切号...");
        }
        mark_current_quota_depleted(&state);
        if let Some(resp) = dispatch_quota_switch_retry(
            &state,
            &method,
            &upstream_url,
            &base_headers,
            &body_bytes,
            session_key.as_deref(),
            SwitchReason::Http429,
        )
        .await
        {
            return Ok(resp);
        }
        // 切号失败/账号耗尽 → 缓冲原始 429 返回
        return Ok(Response::builder()
            .status(429)
            .header("content-type", "application/json")
            .body(full_body(resp_bytes))
            .unwrap_or_else(|_| error_response(StatusCode::TOO_MANY_REQUESTS, "429")));
    }

    // 7.5 上游容量满 → 同号 backoff retry，不切号
    // 典型场景：OpenAI 模型池过载，返回 5xx + body "Selected model is at capacity..."
    // 或 HTTP 200 + JSON body 含 server_overloaded / at capacity（codex App 内部 API
    // 调用偶尔会用这种）。两种都不是单号问题，切号也撞同样错；同号等几秒重试就能继续。
    let is_json_response = upstream_resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("json"))
        .unwrap_or(false);
    let should_check_capacity_body = (status_code.as_u16() >= 500 && status_code.as_u16() < 600)
        || (status_code == reqwest::StatusCode::OK && is_json_response);
    if should_check_capacity_body {
        let resp_bytes = upstream_resp.bytes().await.unwrap_or_default();
        let body_lower = String::from_utf8_lossy(&resp_bytes).to_lowercase();
        let is_capacity = matches_global_capacity(&body_lower)
            || status_code == reqwest::StatusCode::SERVICE_UNAVAILABLE
            || body_lower.contains("server_is_overloaded")
            || body_lower.contains("slow_down");
        if is_capacity {
            println!(
                "[Proxy] 上游 {} + 容量满，同号 backoff retry...",
                status_code
            );
            for attempt in 1..=3u64 {
                let backoff = std::time::Duration::from_secs(2 * attempt);
                tokio::time::sleep(backoff).await;
                let (retry_token, _) =
                    match resolve_token_with_affinity(&state, session_key.as_deref()).await {
                        Ok((t, c, _, _)) => (t, c),
                        Err(_) => continue,
                    };
                if let Ok(retry_resp) = forward_with_token(
                    &state,
                    &method,
                    &upstream_url,
                    &base_headers,
                    &body_bytes,
                    &retry_token,
                )
                .await
                {
                    let s = retry_resp.status();
                    if s == reqwest::StatusCode::OK {
                        println!("[Proxy] 容量满同号 retry 第 {} 次成功", attempt);
                        // 200 + SSE 走 bootstrap，否则透传
                        if is_sse_response(&retry_resp) {
                            let h = retry_resp.headers().clone();
                            let stream = retry_resp.bytes_stream().boxed();
                            let resp = build_streaming_response_with_bootstrap(
                                state.clone(),
                                s,
                                h,
                                stream,
                                method.clone(),
                                upstream_url.clone(),
                                base_headers.clone(),
                                body_bytes.clone(),
                                session_affinity_ctx.clone(),
                            );
                            return Ok(resp);
                        }
                        return Ok(build_stream_response(
                            retry_resp,
                            Some(state.tracker.clone()),
                            session_affinity_ctx.clone(),
                        ));
                    }
                    if s.as_u16() >= 500 && s.as_u16() < 600 {
                        // 还是 5xx，下一轮 backoff
                        continue;
                    }
                    // 其他 status：当作正常响应退出 retry 透传
                    return Ok(build_stream_response(
                        retry_resp,
                        Some(state.tracker.clone()),
                        session_affinity_ctx.clone(),
                    ));
                }
            }
            println!("[Proxy] 容量满同号 retry 三次都失败，降级走切号兜底");
            // 撑不住 → 当 quota 路径处理（切号），最后兜底也失败再返 502
            if let Some(resp) = dispatch_quota_switch_retry(
                &state,
                &method,
                &upstream_url,
                &base_headers,
                &body_bytes,
                session_key.as_deref(),
                SwitchReason::Http429,
            )
            .await
            {
                return Ok(resp);
            }
            // 全部失败 → 把缓冲下来的原始 5xx body 转一个 generic 502，**不带原文**
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "上游容量满且重试无果",
            ));
        }
        // 不是容量满的 5xx → 缓冲下来的 body 透传给 codex
        return Ok(Response::builder()
            .status(status_code.as_u16())
            .header("content-type", "application/json")
            .body(full_body(resp_bytes))
            .unwrap_or_else(|_| error_response(StatusCode::BAD_GATEWAY, "5xx 透传")));
    }

    // 7.6 其他 4xx（400/404/422 等）：上游通常返 {"detail":"Bad Request"} 一类的 FastAPI
    // 错误体。proxy 不切号、不重试，但把 path + body 前 1KB 写 log，方便排错。
    if status_code.is_client_error()
        && status_code != reqwest::StatusCode::UNAUTHORIZED
        && status_code != reqwest::StatusCode::FORBIDDEN
        && status_code != reqwest::StatusCode::TOO_MANY_REQUESTS
    {
        let resp_bytes = upstream_resp.bytes().await.unwrap_or_default();
        let preview: String = String::from_utf8_lossy(&resp_bytes)
            .chars()
            .take(1024)
            .collect();
        println!(
            "[Proxy] 上游 {} {} body: {}",
            status_code.as_u16(),
            upstream_url,
            preview
        );
        return Ok(Response::builder()
            .status(status_code.as_u16())
            .header("content-type", "application/json")
            .body(full_body(resp_bytes))
            .unwrap_or_else(|_| error_response(StatusCode::BAD_GATEWAY, "4xx 透传失败")));
    }

    // 8. 成功响应（200 + SSE）→ 立刻返回 Response，body 流内部跑 bootstrap+心跳+切号
    if status_code == reqwest::StatusCode::OK && is_sse_response(&upstream_resp) {
        let resp_status = upstream_resp.status();
        let resp_headers = upstream_resp.headers().clone();
        let raw_stream = upstream_resp.bytes_stream().boxed();

        let resp = build_streaming_response_with_bootstrap(
            state.clone(),
            resp_status,
            resp_headers,
            raw_stream,
            method.clone(),
            upstream_url.clone(),
            base_headers.clone(),
            body_bytes.clone(),
            session_affinity_ctx.clone(),
        );
        // 后台检查预防性切号（保持原行为）
        let state_clone = state.clone();
        tokio::spawn(async move {
            if should_preemptive_switch(&state_clone)
                && !current_has_luna_reserve_for_request(&state_clone, &body_bytes)
            {
                if state_clone
                    .switching
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    if let PickResult::Found { id, .. } = pick_next_account(&state_clone) {
                        let _ = do_switch(&state_clone, &id, SwitchReason::QuotaThreshold);
                    }
                    state_clone.switching.store(false, Ordering::SeqCst);
                }
            }
        });
        return Ok(resp);
    }

    // 9. 非 SSE / 其它 status → 旧的透传路径
    let resp = build_stream_response(
        upstream_resp,
        Some(state.tracker.clone()),
        session_affinity_ctx,
    );

    // 后台检查预防性切号
    let state_clone = state.clone();
    tokio::spawn(async move {
        if should_preemptive_switch(&state_clone)
            && !current_has_luna_reserve_for_request(&state_clone, &body_bytes)
        {
            if state_clone
                .switching
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                if let PickResult::Found { id, .. } = pick_next_account(&state_clone) {
                    let _ = do_switch(&state_clone, &id, SwitchReason::QuotaThreshold);
                }
                state_clone.switching.store(false, Ordering::SeqCst);
            }
        }
    });

    Ok(resp)
}

/// client 模式：让 Server 仲裁切号，然后用新 token 重试
async fn try_remote_switch_and_retry(
    state: &ProxyState,
    method: &hyper::Method,
    upstream_url: &str,
    base_headers: &reqwest::header::HeaderMap,
    body: &Bytes,
    session_key: Option<&str>,
    reason_label: &str,
) -> Option<Response<ProxyBody>> {
    let (current_id, primary, fallback, secret) = {
        let store = state.store.lock().ok()?;
        (
            store.current.clone(),
            store.settings.remote_server_url.clone(),
            store.settings.remote_server_url_fallback.clone(),
            store.settings.remote_shared_secret.clone(),
        )
    };
    if secret.is_empty() {
        eprintln!("[Proxy] client 模式但未配置 remote_shared_secret");
        return None;
    }
    let base = match crate::remote_client::resolve_base_url(&primary, &fallback).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[Proxy] 解析 Server 地址失败: {}", e);
            return None;
        }
    };

    for attempt in 0..MAX_429_RETRIES {
        let outcome = match crate::remote_client::request_switch(
            &base,
            &secret,
            current_id.as_deref(),
            reason_label,
        )
        .await
        {
            Ok(o) => o,
            Err(e) => {
                eprintln!("[Proxy] 向 Server 请求切号失败: {}", e);
                return None;
            }
        };
        if outcome.exhausted {
            eprintln!("[Proxy] Server 告知无可用账号，停止重试");
            return None;
        }
        let Some(new_current) = outcome.current.clone() else {
            return None;
        };
        // 把 Server 的 current 同步到本机（拉 token + 写 auth.json）
        if let Err(e) = adopt_remote_current(state, &base, &secret, &new_current).await {
            eprintln!("[Proxy] 采纳 Server current 失败: {}", e);
            return None;
        }
        invalidate_remote_token_cache();
        let (new_token, _) = match get_current_token(state).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[Proxy] 获取新 token 失败: {}", e);
                return None;
            }
        };
        // 切号到新账号 → prompt_cache_key 拼 account_id + 剥 x-codex-turn-state
        let body_for_new = rewrite_prompt_cache_key(body, &new_current);
        let headers_no_ts = headers_without_turn_state(base_headers);
        match forward_and_bootstrap(
            state,
            method,
            upstream_url,
            &headers_no_ts,
            &body_for_new,
            &new_token,
            session_key,
        )
        .await
        {
            BootstrappedForward::Ok(resp) => {
                state.stats.auto_switches.fetch_add(1, Ordering::Relaxed);
                let _ = state
                    .app_handle
                    .emit("proxy-account-switched", &outcome.name.unwrap_or_default());
                return Some(resp);
            }
            BootstrappedForward::RateLimit | BootstrappedForward::Capacity => {
                println!(
                    "[Proxy] 第 {} 次 Server 切号后仍限额/容量满，再试",
                    attempt + 1
                );
                continue;
            }
            BootstrappedForward::Unauthorized => {
                // Server 给的 token 失效（罕见，Server 应该已经 refresh 过了）。继续 retry，
                // 下一轮 request_switch 会让 Server 选别的号
                println!("[Proxy] 第 {} 次 Server 切号 token 失效，再试", attempt + 1);
                continue;
            }
            BootstrappedForward::Banned => {
                println!(
                    "[Proxy] 第 {} 次 Server 切号目标号疑似封号，再试",
                    attempt + 1
                );
                // Server 那侧的封号判定由 Server 自己处理；本机继续向 Server 询问
                continue;
            }
            BootstrappedForward::Failed(e) => {
                eprintln!("[Proxy] 重试请求失败: {}", e);
                return None;
            }
        }
    }
    None
}

/// 把 Server 的 current 采纳到本机 store：拉 token、写 auth.json、更新 store.current
async fn adopt_remote_current(
    state: &ProxyState,
    base: &str,
    secret: &str,
    new_id: &str,
) -> Result<(), String> {
    let t = crate::remote_client::fetch_token(base, secret, new_id).await?;
    // 先检查账号是否存在（短作用域 lock）
    let had_account = {
        let store = state.store.lock().map_err(|e| e.to_string())?;
        store.accounts.contains_key(new_id)
    };
    if !had_account {
        // Server 上有但本机没有 → 拉整个账号列表同步
        if let Ok(list) = crate::remote_client::list_accounts(base, secret).await {
            if let Ok(mut s) = state.store.lock() {
                for a in list {
                    s.accounts.insert(a.id.clone(), a);
                }
                let _ = s.save();
            }
        }
    }
    // 写入新 token + 更新 current（短作用域 lock，无 await）
    // 注意：anchor 设置时**只更新 store.current**，不动 disk auth.json，
    // 保住手机 bridge 走的 anchor 镜像。proxy 路由走 store.current 的 token，跟 disk 解耦。
    let auth_to_write = {
        let mut store = state.store.lock().map_err(|e| e.to_string())?;
        store.sync_account_from_auth_json(new_id, t.auth_json.clone());
        let auth = store
            .accounts
            .get(new_id)
            .map(|acc| acc.to_codex_auth_value());
        store.current = Some(new_id.to_string());
        let _ = store.save();
        auth
    };
    if let Some(auth) = auth_to_write {
        // anchor-guarded：跳过 anchor 不匹配的写盘
        write_codex_auth_respecting_anchor(state, new_id, &auth);
    }
    // 同 do_switch 的理由：client 模式被 Server 推过来的切号也不该牵连无关 bridge。
    // 真正"该断的"那条 bridge 在 limit 检测里自己会送 Close。
    let _ = state.app_handle.emit("accounts-updated", ());
    Ok(())
}

/// 切号并重试（最多 MAX_429_RETRIES 次）
async fn try_switch_and_retry(
    state: &ProxyState,
    method: &hyper::Method,
    upstream_url: &str,
    base_headers: &reqwest::header::HeaderMap,
    body: &Bytes,
    session_key: Option<&str>,
    reason: SwitchReason,
) -> Option<Response<ProxyBody>> {
    // Pre-flight：记录入口时的 current，以便最后兜底恢复
    let entry_current = state.store.lock().ok().and_then(|s| s.current.clone());

    // current 是 Relay 时按设置决定 401/429 是否自动切走
    {
        let store = state.store.lock().ok();
        let cur_is_relay = store
            .as_ref()
            .and_then(|s| s.current.clone())
            .and_then(|id| {
                store
                    .as_ref()
                    .unwrap()
                    .accounts
                    .get(&id)
                    .map(|a| a.is_relay())
            })
            .unwrap_or(false);
        let allow_out = store
            .map(|s| s.settings.relay_auto_switch_out)
            .unwrap_or(true);
        if cur_is_relay && !allow_out {
            println!(
                "[Proxy] current 是 Relay 且 relay_auto_switch_out=false，不自动切（{:?}）",
                reason
            );
            return None;
        }
    }
    for attempt in 0..MAX_429_RETRIES {
        match pick_next_account(state) {
            PickResult::Found { id, token } => {
                if let Err(e) = do_switch(state, &id, reason.clone()) {
                    eprintln!("[Proxy] 切号失败: {}", e);
                    continue;
                }
                // 切号到新账号 → prompt_cache_key 拼 account_id + 剥 x-codex-turn-state
                let body_for_new = rewrite_prompt_cache_key(body, &id);
                let headers_no_ts = headers_without_turn_state(base_headers);
                match forward_and_bootstrap(
                    state,
                    method,
                    upstream_url,
                    &headers_no_ts,
                    &body_for_new,
                    &token,
                    session_key,
                )
                .await
                {
                    BootstrappedForward::Ok(resp) => {
                        println!("[Proxy] 第 {} 次切号重试成功", attempt + 1);
                        return Some(resp);
                    }
                    BootstrappedForward::RateLimit => {
                        println!("[Proxy] 第 {} 次切号后仍限额（status/流内）", attempt + 1);
                        mark_current_quota_depleted(state);
                        continue;
                    }
                    BootstrappedForward::Capacity => {
                        println!(
                            "[Proxy] 第 {} 次切号目标号也容量满（全局过载），再试下一个",
                            attempt + 1
                        );
                        // 容量满不是该号的问题，不要 mark_quota_depleted；直接换下一个看运气
                        continue;
                    }
                    BootstrappedForward::Banned => {
                        println!("[Proxy] 第 {} 次切号目标号疑似封号", attempt + 1);
                        mark_current_banned(state);
                        continue;
                    }
                    BootstrappedForward::Unauthorized => {
                        // 切到的号 401：多半只是 access_token 过期（rt 还活着）——pick_next
                        // 给的是 store 里的旧 access_token，切号前没刷新。先静默刷新这个号
                        // （do_switch 后它已是 store.current）再重试一次；只有 OAuth 端点给出
                        // 明确登出 / invalid_grant 才标记，网络 / 瞬时 / 跨 IP 吊销一律不标，
                        // 避免把 rt 健康的好号误判成"过期"（团队/免费号被切号风暴扫射误伤）。
                        match silent_refresh_current(state).await {
                            SilentRefreshOutcome::Refreshed(fresh) => {
                                match forward_and_bootstrap(
                                    state,
                                    method,
                                    upstream_url,
                                    &headers_no_ts,
                                    &body_for_new,
                                    &fresh,
                                    session_key,
                                )
                                .await
                                {
                                    BootstrappedForward::Ok(resp) => {
                                        println!(
                                            "[Proxy] 第 {} 次切号目标号刷新后成功",
                                            attempt + 1
                                        );
                                        return Some(resp);
                                    }
                                    _ => {
                                        // 刷新出新 token 仍 401 = 瞬时/跨 IP 吊销，本轮跳过不标记
                                        println!(
                                            "[Proxy] 第 {} 次切号目标号刷新后仍 401（瞬时），跳过不标记",
                                            attempt + 1
                                        );
                                        continue;
                                    }
                                }
                            }
                            SilentRefreshOutcome::LoggedOut => {
                                println!(
                                    "[Proxy] 第 {} 次切号目标号已登出/RT 轮换，标记 is_logged_out",
                                    attempt + 1
                                );
                                if let Ok(mut store) = state.store.lock() {
                                    if let Some(acc) = store.accounts.get_mut(&id) {
                                        acc.is_logged_out = true;
                                        let _ = store.save();
                                    }
                                }
                                continue;
                            }
                            SilentRefreshOutcome::NoRefreshToken => {
                                println!(
                                    "[Proxy] 第 {} 次切号目标号缺 refresh_token，标记 is_token_invalid",
                                    attempt + 1
                                );
                                if let Ok(mut store) = state.store.lock() {
                                    if let Some(acc) = store.accounts.get_mut(&id) {
                                        acc.is_token_invalid = true;
                                        let _ = store.save();
                                    }
                                }
                                continue;
                            }
                            SilentRefreshOutcome::OtherError(e) => {
                                println!(
                                    "[Proxy] 第 {} 次切号目标号刷新瞬时失败（{}），跳过不标记",
                                    attempt + 1,
                                    e
                                );
                                continue;
                            }
                        }
                    }
                    BootstrappedForward::Failed(e) => {
                        eprintln!("[Proxy] 切号后转发失败: {}", e);
                        continue;
                    }
                }
            }
            PickResult::Exhausted { earliest_reset } => {
                let msg = if let Some(ts) = earliest_reset {
                    let dt = chrono::DateTime::from_timestamp(ts, 0)
                        .map(|d| d.with_timezone(&chrono::Local).format("%H:%M").to_string())
                        .unwrap_or_else(|| "未知".to_string());
                    format!("所有账号额度已耗尽，最早恢复：{}", dt)
                } else {
                    "所有账号额度已耗尽".to_string()
                };
                eprintln!("[Proxy] {}", msg);
                let _ = state.app_handle.emit("proxy-all-exhausted", &msg);
                restore_current_if_flagged(state, entry_current.as_deref());
                return None;
            }
        }
    }
    restore_current_if_flagged(state, entry_current.as_deref());
    None
}

/// `try_switch_and_retry` 的 retry 循环里每次 attempt 都会先 `do_switch` 改
/// `store.current`，所以失败收尾时 store.current 通常停在最后一个被试过的（已被
/// 标记为 banned / token_invalid / logged_out 的）坏账号上。下次 proxy 收到请求
/// 会用这个坏号 → 又 401/429 → 又走 try_switch_and_retry → 死循环。
///
/// 这里收尾：如果 `store.current` 是已标记的坏号，尝试把 current 改回入口时的
/// `entry_id`（如果它还健康），否则随便找一个健康账号顶上。**不发任何请求**，
/// 纯本地 store 矫正。
fn restore_current_if_flagged(state: &ProxyState, entry_id: Option<&str>) {
    let mut store = match state.store.lock() {
        Ok(s) => s,
        Err(_) => return,
    };
    let current_id = match store.current.clone() {
        Some(id) => id,
        None => return,
    };
    let current_flagged = store
        .accounts
        .get(&current_id)
        .map(|a| a.is_banned || a.is_token_invalid || a.is_logged_out)
        .unwrap_or(false);
    if !current_flagged {
        return; // current 健康，不动
    }

    // 先看 entry 那个号还能不能用
    let entry_ok = entry_id
        .filter(|eid| *eid != current_id.as_str())
        .and_then(|eid| store.accounts.get(eid))
        .map(|a| !a.is_banned && !a.is_token_invalid && !a.is_logged_out)
        .unwrap_or(false);
    // 兜底候选：遵守 `relay_auto_switch_in` 约束 —— 默认 false 时不能挑 Relay
    // 类账号（否则用户手切到订阅号、自动切链失败后会被收尾切到 GLM/MiMo 这种
    // 中转，违反"非订阅号只能手动切"的预期）。
    let allow_relay = store.settings.relay_auto_switch_in;
    let revert_to: Option<String> = if entry_ok {
        entry_id.map(String::from)
    } else {
        store
            .accounts
            .iter()
            .find(|(id, a)| {
                id.as_str() != current_id.as_str()
                    && !a.is_banned
                    && !a.is_token_invalid
                    && !a.is_logged_out
                    && (allow_relay || !a.is_relay())
            })
            .map(|(id, _)| id.clone())
    };
    if let Some(target_id) = revert_to {
        let target_name = store
            .accounts
            .get(&target_id)
            .map(|a| a.name.clone())
            .unwrap_or_default();
        println!(
            "[Proxy] 切号链失败收尾：current 是坏号 {}, 矫正回 {}",
            current_id, target_id
        );
        if let Err(e) = store.switch_to(&target_id, true) {
            eprintln!("[Proxy] 收尾矫正 switch_to 失败: {}", e);
        } else {
            let _ = store.save();
            invalidate_remote_token_cache();
            let _ = state
                .app_handle
                .emit("proxy-account-switched", &target_name);
            let _ = state.app_handle.emit("accounts-updated", ());
        }
    } else {
        eprintln!("[Proxy] 切号链失败收尾：无健康账号可恢复，current 仍指向坏号");
    }
}

// ────────────────────────────────────────────────────────────────
// HTTP 转发与响应构建
// ────────────────────────────────────────────────────────────────

/// 把 Server 的 remote-api URL（端口通常是 18081）换成 proxy URL（默认 18080）
fn derive_server_proxy_url(api_url: &str, proxy_port: u16) -> Option<String> {
    let u = reqwest::Url::parse(api_url.trim()).ok()?;
    let host = u.host_str()?;
    Some(format!("{}://{}:{}", u.scheme(), host, proxy_port))
}

/// 切号到新账号时调用：复制 headers + 剥掉 `x-codex-turn-state`。
/// 这个 header 是 OpenAI 服务端给的 sticky-routing token，绑定到颁发它的账号/分片。
/// 老账号的 turn-state 在新账号上无效甚至有害（可能 401 或路由错误）。
/// codex-rs 自己的 client.rs:360-370 注释也明说"must not send between different turns"。
/// 切号 = 跨 turn，必须剥。
fn headers_without_turn_state(base: &reqwest::header::HeaderMap) -> reqwest::header::HeaderMap {
    let mut h = base.clone();
    h.remove("x-codex-turn-state");
    h
}

/// 找到本次 bearer token 对应的 ChatGPT workspace account id。
///
/// 优先检查 current，兼容普通切号；再按 token 精确查找，兼容 session affinity / hard route
/// 在不修改 current 的情况下临时使用其它账号。只有 ChatGPT OAuth 账号才返回 account id，
/// OpenAI API key / Relay 必须移除客户端遗留的 `chatgpt-account-id`。
fn chatgpt_account_id_for_token(state: &ProxyState, token: &str) -> Option<String> {
    let store = state.store.lock().ok()?;

    let matches_token = |account: &crate::account::Account| {
        account.is_chatgpt_oauth()
            && AccountStore::extract_access_token(&account.auth_json).as_deref() == Some(token)
    };

    if let Some(current) = store
        .current
        .as_deref()
        .and_then(|id| store.accounts.get(id))
    {
        if matches_token(current) {
            return AccountStore::extract_account_id(&current.auth_json);
        }
    }

    store
        .accounts
        .values()
        .find(|account| matches_token(account))
        .and_then(|account| AccountStore::extract_account_id(&account.auth_json))
}

/// 最终出站前原子绑定 bearer token 与其 ChatGPT workspace account id。
/// 先删除任何客户端/桌面壳传入的旧 account id，再按本次实际选择的 token 重建。
fn bind_reqwest_upstream_identity(
    headers: &mut reqwest::header::HeaderMap,
    token: &str,
    chatgpt_account_id: Option<&str>,
) {
    headers.remove(reqwest::header::AUTHORIZATION);
    headers.remove(CHATGPT_ACCOUNT_ID_HEADER);

    if let Ok(value) = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token)) {
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    if let Some(account_id) = chatgpt_account_id {
        if let Ok(value) = reqwest::header::HeaderValue::from_str(account_id) {
            headers.insert(
                reqwest::header::HeaderName::from_static(CHATGPT_ACCOUNT_ID_HEADER),
                value,
            );
        }
    }
}

fn bind_websocket_upstream_identity(
    headers: &mut tungstenite::http::HeaderMap,
    token: &str,
    chatgpt_account_id: Option<&str>,
) {
    headers.remove(hyper::header::AUTHORIZATION);
    headers.remove(CHATGPT_ACCOUNT_ID_HEADER);

    if let Ok(value) = HeaderValue::from_str(&format!("Bearer {}", token)) {
        headers.insert(hyper::header::AUTHORIZATION, value);
    }
    if let Some(account_id) = chatgpt_account_id {
        if let Ok(value) = HeaderValue::from_str(account_id) {
            headers.insert(HeaderName::from_static(CHATGPT_ACCOUNT_ID_HEADER), value);
        }
    }
}

/// 构造上游请求的透明转发 header（剔除 host/authorization/connection，注入上游 Host）
fn build_upstream_headers(
    req_headers: &hyper::HeaderMap,
    upstream_host: &str,
) -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    for (name, value) in req_headers {
        let lower = name.as_str().to_ascii_lowercase();
        if lower == "authorization"
            || lower == CHATGPT_ACCOUNT_ID_HEADER
            || lower == "host"
            || lower == "connection"
        {
            continue;
        }
        // `session_id`（下划线）不是官方 codex 客户端会发的 header —— 真实客户端
        // 用的是 `session-id`/`thread-id`（连字符）。它只被 resolve_hard_route
        // 当作本地路由 key 使用，一旦透传给 chatgpt.com 就变成"同一账号上反复出现
        // 的固定非标准 header"，是比随机值更显眼的自动化流量指纹。本地路由用完
        // 就该在这里剥掉，不让它离开这台机器。
        // `x-worker-id`/`x-task-id`：pod-worker 自己的任务追踪 header，同样
        // 从不是官方客户端会发的字段，只对本地/日志有意义，不该离开这台机器。
        // `x-pod-worker-route`：本地硬路由专用 key（见 resolve_hard_route），
        // 同理只对本地有意义。
        // `x-pod-worker-follow-current`：chat 入站的本地选号标记（见
        // WORKER_FOLLOW_CURRENT_HEADER）。chat 入站自己从零构造出站 header，本来
        // 就漏不出去；在这里一并剥掉是为了让"不外泄"成为被强制的性质而不是巧合。
        // 对 Codex 是空操作 —— responses/WS 路径上没有任何客户端会发这个 header。
        if lower == "session_id"
            || lower == "x-worker-id"
            || lower == "x-task-id"
            || lower == "x-pod-worker-route"
            || lower == WORKER_FOLLOW_CURRENT_HEADER
        {
            continue;
        }
        if let Ok(rn) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) {
            if let Ok(rv) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                h.append(rn, rv);
            }
        }
    }
    if let Ok(host_val) = reqwest::header::HeaderValue::from_str(upstream_host) {
        h.insert(reqwest::header::HOST, host_val);
    }
    h
}

/// chat_completions Relay 专用 header 构造：只透传 Accept / User-Agent 等无害的，
/// 不带 codex 私有 header（x-codex-*、session_id、thread_id、OpenAI-Beta、
/// traceparent 等）。
///
/// 历史背景：在 GLM Coding Plan 边缘 WAF 上观测到，只要带 codex 那堆 `x-codex-*`
/// header POST `/api/coding/paas/v4/chat/completions`，请求就会被路由到一个
/// 不接 POST 的 handler，返回 `405 METHOD_NOT_ALLOWED`。curl 同样的 URL + body
/// 但不带 codex header，照样 200。chat_completions 协议本身只需要 Auth + JSON。
fn build_chat_relay_upstream_headers(upstream_host: &str) -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    h.insert(
        reqwest::header::ACCEPT,
        reqwest::header::HeaderValue::from_static("application/json, text/event-stream"),
    );
    h.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static("codex-switcher-relay/1.0"),
    );
    if let Ok(host_val) = reqwest::header::HeaderValue::from_str(upstream_host) {
        h.insert(reqwest::header::HOST, host_val);
    }
    h
}

/// client 模式专用：把已解析好的请求部件原样透传到 Server 的 proxy 端口。
/// 返回原始 reqwest::Response，由调用方决定是流式透传还是（针对 402 等）缓冲后重试。
async fn forward_to_server_parts(
    state: &ProxyState,
    method: &hyper::Method,
    path_and_query: &str,
    req_headers: &hyper::HeaderMap,
    body: &Bytes,
) -> Result<reqwest::Response, String> {
    let (primary, fallback, proxy_port) = {
        let s = state.store.lock().map_err(|e| e.to_string())?;
        (
            s.settings.remote_server_url.clone(),
            s.settings.remote_server_url_fallback.clone(),
            s.settings.proxy_port,
        )
    };

    let api_base = if !fallback.trim().is_empty() {
        fallback.trim().to_string()
    } else {
        crate::remote_client::resolve_base_url(&primary, &fallback)
            .await
            .map_err(|e| format!("Server 不可达: {}", e))?
    };
    let proxy_base = derive_server_proxy_url(&api_base, proxy_port)
        .ok_or_else(|| format!("无法从 {} 构造 Server proxy URL", api_base))?;
    let upstream_url = format!("{}{}", proxy_base, path_and_query);
    println!("[Proxy] → server forward: {} {}", method, upstream_url);

    let mut fwd_headers = reqwest::header::HeaderMap::new();
    for (name, value) in req_headers {
        let lower = name.as_str().to_ascii_lowercase();
        if lower == "host"
            || lower == "authorization"
            || lower == CHATGPT_ACCOUNT_ID_HEADER
            || lower == "connection"
        {
            continue;
        }
        if let Ok(rn) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) {
            if let Ok(rv) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                fwd_headers.append(rn, rv);
            }
        }
    }

    let reqwest_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST);
    // Server 永远是 LAN/ZeroTier 私有 IP，必须绕开系统代理（防 Clash 截走）。
    // state.client 是共享 client、走系统代理用于打 ChatGPT/Relay 上游，这里另起一个。
    let no_proxy_client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("构建 no_proxy client 失败: {}", e))?;
    no_proxy_client
        .request(reqwest_method, &upstream_url)
        .headers(fwd_headers)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| format!("转发到 Server 失败: {e:?}"))
}

/// 写 `~/.codex/auth.json` 但**尊重手机锚约束**：anchor 设置了且 account_id != anchor
/// 时跳过写盘并 log，避免把 anchor 的 disk 镜像覆盖掉、手机 bridge 鉴权挂。
///
/// 适用于"被动"写盘路径：silent_refresh、adopt_remote_current、proxy 拿 Server token
/// 后回写本机这类 background 操作。手动切号（lib.rs::switch_account）走的是"主动"路径，
/// 用户明知道在切，那条继续无视 anchor、覆盖 disk。
fn write_codex_auth_respecting_anchor(
    state: &ProxyState,
    account_id: &str,
    auth: &serde_json::Value,
) {
    let blocked = state
        .store
        .lock()
        .map(|s| !s.should_write_disk_for(account_id))
        .unwrap_or(false);
    if blocked {
        println!(
            "[Proxy] 手机锚生效，跳过写 ~/.codex/auth.json（{} != anchor）",
            account_id
        );
        return;
    }
    if let Err(e) = crate::account::AccountStore::write_codex_auth_extended_expiry(auth) {
        eprintln!("[Proxy] 写 ~/.codex/auth.json 失败: {}", e);
    }
}

/// 在 client mode 把 forward_to_server_parts 的响应 peek 一下首 chunk，看是否撞限额；
/// 撞了就调 Server /switch + retry，最多 `max_retries` 次。
///
/// **核心目的**：实现"无损切号" —— 让 codex 看不到 usage_limit_reached 错误。
/// 之前 client mode HTTP 路径裸透传响应（`build_stream_response(mini_resp, None, None)`），
/// chatgpt.com 返的 usage_limit error 直接传到 codex Desktop UI，用户看到 "已切号但还是错"
/// 的错觉 —— 实际上 WS 路径异步切了号，但这条 HTTP 请求已经把 error body 透回去了。
///
/// 返回值：
/// - `Ok(Some(resp))`：要返给 codex 的响应（成功或最后一次重试失败都走这里）
/// - `Ok(None)`：402 Deactivated，让外层走 try_local_fallback 老路径
/// - `Err(e)`：forward_to_server 本身报错（Server 不可达），让外层 fall-through 到本地直连
async fn forward_to_server_with_silent_retry(
    state: &ProxyState,
    method: &hyper::Method,
    path_and_query: &str,
    req_headers: &hyper::HeaderMap,
    body: &Bytes,
    max_retries: u32,
) -> Result<Option<Response<ProxyBody>>, String> {
    // peek 限额检测复用 PER_ACCOUNT_LIMIT_KEYWORDS：除了 *_reached / *_exceeded 等
    // wire code，还含人类可读文案 "usage limit" / "hit your usage limit" / "too many
    // requests" —— Team/组织管理员设的用量上限文案
    // ("You've hit your usage limit. ... send a request to your admin ...") 的 code
    // 不一定是 usage_limit_reached，必须靠 message 文本兜底，否则不切号。
    //
    // Spark 请求例外：Spark 是 Pro 专属子限额，跟基础额度是两个池子。它的 429 不该触发
    // 切号（Server 端 handle_request 也对 spark 429 原样透回），这里把 max_retries 归零，
    // 只 forward 一次、不调 /switch，直接把 429 透回 Spark 调用方。
    let max_retries = if request_is_spark_model(body) {
        0
    } else {
        max_retries
    };
    for attempt in 0..=max_retries {
        let mini_resp =
            match forward_to_server_parts(state, method, path_and_query, req_headers, body).await {
                Ok(r) => r,
                Err(e) => return Err(e),
            };
        let status = mini_resp.status();
        let headers = mini_resp.headers().clone();

        // 402 deactivated 走外层老路径处理 try_local_fallback
        if status == reqwest::StatusCode::PAYMENT_REQUIRED {
            // 注意：这里没消费 body —— 外层会重新调用一次拿 body，但 Server 此时
            // current 账号没变（我们没 switch），第二次调返回相同结果。可接受。
            return Ok(None);
        }

        // peek 第一个 chunk，看是否限额（限额 frame 通常 <2KB，第一个 chunk 一定能拿到）
        let mut stream = mini_resp.bytes_stream();
        let first_chunk = match stream.next().await {
            Some(Ok(c)) => c,
            Some(Err(e)) => {
                return Err(format!("silent_retry: 读首 chunk 失败: {}", e));
            }
            None => Bytes::new(),
        };

        let peek_lower = String::from_utf8_lossy(&first_chunk).to_lowercase();
        let is_rate_limit = PER_ACCOUNT_LIMIT_KEYWORDS
            .iter()
            .any(|kw| peek_lower.contains(kw));

        if is_rate_limit && attempt < max_retries {
            println!(
                "[Proxy] silent_retry: client HTTP 响应限额，切号重试 ({}/{})",
                attempt + 1,
                max_retries
            );
            // 调 Server /switch；失败也继续 retry（也许 Server 自己切了号了）
            if let Err(e) = call_remote_switch_silently(state).await {
                eprintln!("[Proxy] silent_retry: /switch 调用失败: {}", e);
            }
            // 把这次的 stream 丢掉，下一轮重 forward
            drop(stream);
            // 给 Server 一点时间把 current 切完毕 + token 同步
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            continue;
        }

        // 不限额，或最后一次尝试 —— 把 first_chunk 当 prefix，剩余 stream 续上
        let rest = stream.boxed();
        let resp = build_stream_response_from_parts(status, headers, first_chunk, rest, None, None);
        if is_rate_limit {
            println!(
                "[Proxy] silent_retry: max_retries={} 用完仍限额，把最后一次响应透回 codex",
                max_retries
            );
        }
        return Ok(Some(resp));
    }
    unreachable!("retry loop 总要返回")
}

/// 调 Server /switch 让它切换 current 账号。
/// silent_retry 用，不暴露错误细节给上层（已经在 log 里打了）。
async fn call_remote_switch_silently(state: &ProxyState) -> Result<(), String> {
    let (primary, fallback, secret, cur_id) = {
        let s = state.store.lock().map_err(|e| e.to_string())?;
        (
            s.settings.remote_server_url.clone(),
            s.settings.remote_server_url_fallback.clone(),
            s.settings.remote_shared_secret.clone(),
            s.current.clone(),
        )
    };
    if secret.is_empty() {
        return Err("未配置 remote_shared_secret".to_string());
    }
    let base = crate::remote_client::resolve_base_url(&primary, &fallback)
        .await
        .map_err(|e| format!("resolve_base_url: {}", e))?;
    let outcome = crate::remote_client::request_switch(
        &base,
        &secret,
        cur_id.as_deref(),
        "silent retry: client HTTP usage_limit_reached",
    )
    .await?;
    if outcome.switched {
        println!(
            "[Proxy] silent_retry: Server 已切到 {} ({})",
            outcome.name.clone().unwrap_or_else(|| "?".to_string()),
            outcome
                .current
                .clone()
                .unwrap_or_else(|| "(unknown id)".to_string())
        );
    } else {
        println!(
            "[Proxy] silent_retry: Server switch returned switched=false（可能全部 exhausted）"
        );
    }
    Ok(())
}

/// client 模式回退路径：当 Server 不可达或 Server 告知无可用账号时，尝试使用本机账号直连上游。
/// - 挑一个未封号且有额度的本地账号
/// - 本地 store.current 切到该账号（标记切号来源 RemoteFallback）
/// - 用其 token 直接打 OpenAI 上游
/// 若本机无可用账号则返回 None
async fn try_local_fallback(
    state: &ProxyState,
    method: &hyper::Method,
    path_and_query: &str,
    req_headers: &hyper::HeaderMap,
    body: &Bytes,
    session_key: Option<&str>,
) -> Option<Response<ProxyBody>> {
    let PickResult::Found { id, token } = pick_next_account(state) else {
        eprintln!("[Proxy] 本地回退失败：无可用账号");
        return None;
    };

    // 把本机 current 切到回退账号（也顺便写 auth.json 以便 UI/其它进程感知）
    if let Err(e) = do_switch(state, &id, SwitchReason::RemoteFallback) {
        eprintln!("[Proxy] 本地回退切号失败: {}", e);
        return None;
    }

    // 根据 token 形态路由上游（Relay 类型 sk- 不以 eyJ 开头，is_chatgpt 自然 false）
    let is_chatgpt = token.starts_with("eyJ");
    let relay_base_url = account_relay_base_url(state, &id);
    let (upstream_url, upstream_host) =
        get_upstream(is_chatgpt, relay_base_url.as_deref(), path_and_query);
    let base_headers = build_upstream_headers(req_headers, &upstream_host);
    // 切号到新账号 → prompt_cache_key 拼 account_id + 剥 x-codex-turn-state
    let body_for_new = rewrite_prompt_cache_key(body, &id);
    let headers_no_ts = headers_without_turn_state(&base_headers);
    match forward_and_bootstrap(
        state,
        method,
        &upstream_url,
        &headers_no_ts,
        &body_for_new,
        &token,
        session_key,
    )
    .await
    {
        BootstrappedForward::Ok(resp) => {
            println!("[Proxy] 本地回退转发成功");
            Some(resp)
        }
        BootstrappedForward::RateLimit => {
            // 回退账号也限额：交回 None 让上层报错（None 时 Server 路径会返回 Server 的 402/原错误）
            println!("[Proxy] 本地回退账号也已限额");
            mark_current_quota_depleted(state);
            None
        }
        BootstrappedForward::Capacity => {
            println!("[Proxy] 本地回退碰到全局容量满（不是单号问题）");
            None
        }
        BootstrappedForward::Banned => {
            println!("[Proxy] 本地回退账号疑似封号");
            mark_current_banned(state);
            None
        }
        BootstrappedForward::Unauthorized => {
            // 回退号 401：多半只是 access_token 过期（pick_next 给的是旧 token，没刷新）。
            // do_switch 后它已是 current，先静默刷新再重试一次；只有明确登出 / 缺 rt 才标记，