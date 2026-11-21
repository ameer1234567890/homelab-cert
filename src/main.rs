use axum::{
    extract::{Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use hmac::{Hmac, Mac};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rsa::{
    pkcs8::{EncodePrivateKey, LineEnding},
    RsaPrivateKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    ops::Deref,
    os::unix::fs::OpenOptionsExt,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

type R<T> = Result<T, String>;
fn es<E: ToString>(e: E) -> String { e.to_string() }
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) }
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

// ---------- errors ----------
struct ApiErr(StatusCode, String);
impl From<String> for ApiErr { fn from(s: String) -> Self { ApiErr(StatusCode::BAD_REQUEST, s) } }
impl From<&str> for ApiErr { fn from(s: &str) -> Self { ApiErr(StatusCode::BAD_REQUEST, s.to_string()) } }
impl IntoResponse for ApiErr {
    fn into_response(self) -> Response { (self.0, Json(json!({ "error": self.1 }))).into_response() }
}
type Res = Result<Json<Value>, ApiErr>;

// ---------- data ----------
#[derive(Serialize, Deserialize, Clone)]
struct Cert {
    id: u64, kind: String, name: String, sans: String, days: i64, kt: String,
    cert: String, key: String, not_after: i64, created: i64,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
struct Settings { webhook_url: String, chat_id: String, thresholds: Vec<i64>, enabled: bool }
impl Default for Settings {
    fn default() -> Self {
        Settings { webhook_url: String::new(), chat_id: String::new(), thresholds: vec![30, 14, 7, 1], enabled: true }
    }
}
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct Data { next_id: u64, root: Option<Cert>, certs: Vec<Cert>, settings: Settings, sent: Vec<(u64, i64)> }

struct Inner { d: Mutex<Data>, path: PathBuf, user: String, pass: String, secret: Vec<u8> }
#[derive(Clone)]
struct AppState(Arc<Inner>);
impl Deref for AppState { type Target = Inner; fn deref(&self) -> &Inner { &self.0 } }

fn write_private(path: &FsPath, bytes: &[u8]) -> R<()> {
    let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path).map_err(es)?;
    f.write_all(bytes).map_err(es)?;
    f.sync_all().map_err(es)
}
impl Inner {
    fn lock(&self) -> MutexGuard<'_, Data> { self.d.lock().unwrap_or_else(|e| e.into_inner()) }
    fn save(&self, d: &Data) -> R<()> {
        let tmp = self.path.with_extension("tmp");
        write_private(&tmp, &serde_json::to_vec_pretty(d).map_err(es)?)?;
        fs::rename(&tmp, &self.path).map_err(es)
    }
}

fn view(c: &Cert) -> Value {
    json!({"id": c.id, "kind": c.kind, "name": c.name, "sans": c.sans, "days": c.days, "kt": c.kt,
           "not_after": c.not_after, "created": c.created,
           "days_left": (c.not_after - now()).div_euclid(86400)})
}
fn sv(v: &Value, k: &str, d: &str) -> String { v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string() }
fn nv(v: &Value, k: &str, d: i64) -> R<i64> {
    match v.get(k) {
        None | Some(Value::Null) => Ok(d),
        Some(x) => x.as_i64().or_else(|| x.as_str().and_then(|s| s.trim().parse().ok())).ok_or(format!("{k} must be a number")),
    }
}

// ---------- crypto ----------
fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::OrganizationName, "homelab-cert");
    d.push(DnType::CommonName, cn);
    d
}
fn gen_key(kt: &str, big: bool) -> R<KeyPair> {
    match kt {
        "ec" => KeyPair::generate().map_err(es),
        "rsa" => {
            let k = RsaPrivateKey::new(&mut rand::rngs::OsRng, if big { 4096 } else { 2048 }).map_err(es)?;
            let pem = k.to_pkcs8_pem(LineEnding::LF).map_err(es)?;
            KeyPair::from_pem(pem.as_str()).map_err(es)
        }
        _ => Err("Unknown key type".into()),
    }
}
/// returns (cert pem, key pem, not_after)
fn make_root(cn: &str, years: i64, kt: &str) -> R<(String, String, i64)> {
    let key = gen_key(kt, true)?;
    let t = now();
    let end = t + years * 365 * 86400;
    let mut p = CertificateParams::default();
    p.distinguished_name = dn(cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.not_before = OffsetDateTime::from_unix_timestamp(t - 86400).map_err(es)?;
    p.not_after = OffsetDateTime::from_unix_timestamp(end).map_err(es)?;
    let cert = p.self_signed(&key).map_err(es)?;
    Ok((cert.pem(), key.serialize_pem(), end))
}
fn make_leaf(root: &Cert, name: &str, sans: &[String], days: i64, kt: &str) -> R<(String, String, i64)> {
    let rk = KeyPair::from_pem(&root.key).map_err(es)?;
    let rc = CertificateParams::from_ca_cert_pem(&root.cert).map_err(es)?.self_signed(&rk).map_err(es)?;
    let t = now();
    let end = (t + days * 86400).min(root.not_after);
    if end <= t { return Err("The root CA has expired - regenerate it".into()); }
    let key = gen_key(kt, false)?;
    let mut p = CertificateParams::new(sans.to_vec()).map_err(|e| format!("Invalid name or address: {e}"))?;
    p.distinguished_name = dn(name);
    p.is_ca = IsCa::NoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    if kt == "rsa" { p.key_usages.push(KeyUsagePurpose::KeyEncipherment); }
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    p.not_before = OffsetDateTime::from_unix_timestamp(t - 300).map_err(es)?;
    p.not_after = OffsetDateTime::from_unix_timestamp(end).map_err(es)?;
    let cert = p.signed_by(&key, &rc, &rk).map_err(es)?;
    Ok((cert.pem(), key.serialize_pem(), end))
}
fn split_sans(name: &str, raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in raw.replace(',', " ").split_whitespace() {
        if !out.iter().any(|o| o == s) { out.push(s.to_string()); }
    }
    if !out.iter().any(|o| o == name) { out.insert(0, name.to_string()); }
    out
}

fn issue(st: &Inner, name: &str, sans_raw: &str, days: i64, kt: &str, renew: Option<u64>) -> R<u64> {
    let root = st.lock().root.clone().ok_or_else(|| "Create the root CA first".to_string())?;
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 { return Err("Name must be 1-64 characters".into()); }
    if !(1..=3650).contains(&days) { return Err("Validity must be 1-3650 days".into()); }
    if kt != "ec" && kt != "rsa" { return Err("Unknown key type".into()); }
    let sans = split_sans(name, sans_raw);
    let (cert, key, na) = make_leaf(&root, name, &sans, days, kt)?;
    let mut d = st.lock();
    let t = now();
    let id = match renew {
        Some(id) => {
            match d.certs.iter_mut().find(|c| c.id == id) {
                Some(c) => {
                    c.cert = cert; c.key = key; c.not_after = na; c.created = t;
                }
                None => return Err("Not found".into()),
            }
            d.sent.retain(|(i, _)| *i != id);
            id
        }
        None => {
            d.next_id += 1;
            let id = d.next_id;
            d.certs.push(Cert { id, kind: "leaf".into(), name: name.into(), sans: sans.join(","), days, kt: kt.into(),
                                cert, key, not_after: na, created: t });
            id
        }
    };
    st.save(&d)?;
    Ok(id)
}

fn replace_root(st: &Inner, name: &str, years: i64, kt: &str) -> R<()> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 { return Err("Root name must be 1-64 characters".into()); }
    if !(1..=30).contains(&years) { return Err("Root validity must be 1-30 years".into()); }
    if kt != "ec" && kt != "rsa" { return Err("Unknown key type".into()); }
    let (cert, key, na) = make_root(name, years, kt)?;
    let mut nr = Cert { id: 0, kind: "root".into(), name: name.into(), sans: String::new(), days: 365 * years,
                        kt: kt.into(), cert, key, not_after: na, created: now() };
    let leafs = st.lock().certs.clone();
    let mut out = Vec::new();
    for l in leafs {
        let (c, k, n) = make_leaf(&nr, &l.name, &split_sans(&l.name, &l.sans), l.days, &l.kt)?;
        out.push(Cert { cert: c, key: k, not_after: n, created: now(), ..l });
    }
    let mut d = st.lock();
    let cur = d.root.as_ref().map(|r| r.id);
    nr.id = match cur { Some(i) => i, None => { d.next_id += 1; d.next_id } };
    let mut ids: Vec<u64> = vec![nr.id];
    for o in out {
        ids.push(o.id);
        if let Some(x) = d.certs.iter_mut().find(|x| x.id == o.id) { *x = o; }
    }
    d.sent.retain(|(i, _)| !ids.contains(i));
    d.root = Some(nr);
    st.save(&d)
}

// ---------- notifications ----------
fn notify(text: &str, s: &Settings) -> R<()> {
    let url = s.webhook_url.trim();
    if url.is_empty() { return Err("Add a webhook URL first".into()); }
    let (target, body) = if url.contains("api.telegram.org") {
        let (base, query) = url.split_once('?').unwrap_or((url, ""));
        let chat = if !s.chat_id.is_empty() {
            s.chat_id.clone()
        } else {
            query.split('&').find_map(|kv| kv.strip_prefix("chat_id=")).unwrap_or("").to_string()
        };
        if chat.is_empty() { return Err("Telegram needs a chat ID".into()); }
        let mut b = base.trim_end_matches('/').to_string();
        if !b.ends_with("/sendMessage") { b.push_str("/sendMessage"); }
        (b, json!({"chat_id": chat, "text": text}))
    } else {
        (url.to_string(), json!({"text": text, "content": text, "message": text}))
    };
    // errors never echo the URL (it may contain a bot token)
    ureq::post(&target)
        .timeout(Duration::from_secs(10))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .map(|_| ())
        .map_err(|e| match e {
            ureq::Error::Status(c, _) => format!("Webhook failed: HTTP {c}"),
            _ => "Webhook failed: could not connect".to_string(),
        })
}

fn check(st: &Inner) -> R<()> {
    let s = st.lock().settings.clone();
    if !s.enabled || s.webhook_url.trim().is_empty() { return Ok(()); }
    let mut ths = s.thresholds.clone();
    ths.push(0);
    ths.sort_unstable();
    ths.dedup();
    let mut lines: Vec<String> = Vec::new();
    let mut marks: Vec<(u64, i64)> = Vec::new();
    {
        let d = st.lock();
        let t = now() as f64;
        for c in d.root.iter().chain(d.certs.iter()) {
            let left = (c.not_after as f64 - t) / 86400.0;
            let due: Vec<i64> = ths.iter().copied().filter(|th| left <= *th as f64 && !d.sent.contains(&(c.id, *th))).collect();
            if due.is_empty() { continue; }
            let state = if left <= 0.0 { "EXPIRED".to_string() } else { format!("expires in {} day(s)", left.ceil() as i64) };
            lines.push(format!("- {} ({}): {}", c.name, if c.kind == "root" { "root CA" } else { "certificate" }, state));
            marks.extend(due.into_iter().map(|th| (c.id, th)));
        }
    }
    if lines.is_empty() { return Ok(()); }
    notify(&format!("homelab-cert: certificate expiry\n{}", lines.join("\n")), &s)?;
    let mut d = st.lock();
    for m in marks { if !d.sent.contains(&m) { d.sent.push(m); } }
    st.save(&d)
}

// ---------- auth ----------
fn sign(st: &Inner, exp: i64) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(&st.secret).expect("hmac key");
    m.update(format!("session|{exp}").as_bytes());
    hex(&m.finalize().into_bytes())
}
fn session_ok(st: &Inner, h: &HeaderMap) -> bool {
    let Some(c) = h.get(header::COOKIE).and_then(|v| v.to_str().ok()) else { return false };
    let Some(tok) = c.split(';').find_map(|p| p.trim().strip_prefix("hc_session=")) else { return false };
    let Some((exp, sig)) = tok.split_once('.') else { return false };
    let Ok(e) = exp.parse::<i64>() else { return false };
    e > now() && bool::from(sign(st, e).as_bytes().ct_eq(sig.as_bytes()))
}
async fn auth(State(st): State<AppState>, req: Request, next: Next) -> Response {
    if session_ok(&st, req.headers()) {
        next.run(req).await
    } else {
        ApiErr(StatusCode::UNAUTHORIZED, "Not signed in".into()).into_response()
    }
}

// ---------- handlers ----------
async fn index() -> Html<&'static str> { Html(include_str!("../static/index.html")) }

async fn login(State(st): State<AppState>, Json(b): Json<Value>) -> Response {
    let (u, p) = (sv(&b, "username", ""), sv(&b, "password", ""));
    let ok = bool::from(u.as_bytes().ct_eq(st.user.as_bytes()) & p.as_bytes().ct_eq(st.pass.as_bytes()));
    if !ok {
        tokio::time::sleep(Duration::from_secs(1)).await;
        return ApiErr(StatusCode::UNAUTHORIZED, "Wrong username or password".into()).into_response();
    }
    let exp = now() + 7 * 86400;
    let cookie = format!("hc_session={exp}.{}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}", sign(&st, exp), 7 * 86400);
    ([(header::SET_COOKIE, cookie)], Json(json!({"ok": true}))).into_response()
}
async fn logout() -> Response {
    ([(header::SET_COOKIE, "hc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string())], Json(json!({"ok": true}))).into_response()
}

async fn state(State(st): State<AppState>) -> Json<Value> {
    let d = st.lock();
    let mut certs: Vec<&Cert> = d.certs.iter().collect();
    certs.sort_by_key(|c| c.not_after);
    Json(json!({
        "user": st.user,
        "root": d.root.as_ref().map(view),
        "settings": d.settings,
        "certs": certs.into_iter().map(view).collect::<Vec<_>>(),
    }))
}

async fn root_create(State(st): State<AppState>, Json(b): Json<Value>) -> Res {
    let name = sv(&b, "name", "Homelab Root CA");
    let kt = sv(&b, "key_type", "ec");
    let years = nv(&b, "years", 10)?;
    let confirm = b.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);
    if st.lock().root.is_some() && !confirm { return Err("Confirm to replace the existing root".into()); }
    tokio::task::spawn_blocking(move || replace_root(&st, &name, years, &kt)).await.map_err(es)??;
    Ok(Json(json!({"ok": true})))
}

async fn cert_create(State(st): State<AppState>, Json(b): Json<Value>) -> Res {
    let (name, sans, kt) = (sv(&b, "name", ""), sv(&b, "sans", ""), sv(&b, "key_type", "ec"));
    let days = nv(&b, "days", 365)?;
    let id = tokio::task::spawn_blocking(move || issue(&st, &name, &sans, days, &kt, None)).await.map_err(es)??;
    Ok(Json(json!({"id": id})))
}

async fn cert_renew(State(st): State<AppState>, Path(id): Path<u64>) -> Res {
    let c = st.lock().certs.iter().find(|c| c.id == id).cloned();
    let Some(c) = c else { return Err(ApiErr(StatusCode::NOT_FOUND, "Not found".into())) };
    tokio::task::spawn_blocking(move || issue(&st, &c.name, &c.sans, c.days, &c.kt, Some(id))).await.map_err(es)??;
    Ok(Json(json!({"ok": true})))
}

async fn cert_delete(State(st): State<AppState>, Path(id): Path<u64>) -> Res {
    let mut d = st.lock();
    d.certs.retain(|c| c.id != id);
    d.sent.retain(|(i, _)| *i != id);
    st.save(&d)?;
    Ok(Json(json!({"ok": true})))
}

fn safe(n: &str) -> String {
    n.replace('*', "wildcard")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
        .collect()
}

async fn download(State(st): State<AppState>, Path((id, what)): Path<(u64, String)>) -> Response {
    let (c, root) = {
        let d = st.lock();
        (d.root.iter().chain(d.certs.iter()).find(|c| c.id == id).cloned(), d.root.clone())
    };
    let nf = || ApiErr(StatusCode::NOT_FOUND, "Not found".into()).into_response();
    let Some(c) = c else { return nf() };
    let chain = if c.kind == "leaf" {
        format!("{}{}", c.cert, root.as_ref().map(|r| r.cert.as_str()).unwrap_or(""))
    } else {
        c.cert.clone()
    };
    let base = safe(&c.name);
    let pem = "application/x-pem-file";
    let (data, fname, mime): (Vec<u8>, String, &str) = match what.as_str() {
        "cert" => (c.cert.clone().into_bytes(), format!("{base}.crt"), pem),
        "key" => (c.key.clone().into_bytes(), format!("{base}.key"), pem),
        "fullchain" => (chain.into_bytes(), format!("{base}-fullchain.crt"), pem),
        "bundle" => {
            let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            let o = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            let mut files = vec![
                (format!("{base}.crt"), c.cert.clone()),
                (format!("{base}.key"), c.key.clone()),
                (format!("{base}-fullchain.crt"), chain.clone()),
            ];
            if let Some(r) = &root { files.push(("root-ca.crt".to_string(), r.cert.clone())); }
            for (n, t) in files {
                if z.start_file(n, o).is_err() || z.write_all(t.as_bytes()).is_err() {
                    return ApiErr(StatusCode::INTERNAL_SERVER_ERROR, "Could not build zip".into()).into_response();
                }
            }
            let bytes = z.finish().map(|c| c.into_inner()).unwrap_or_default();
            (bytes, format!("{base}.zip"), "application/zip")
        }
        _ => return nf(),
    };
    (
        [
            (header::CONTENT_TYPE, mime.to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{fname}\"")),
        ],
        data,
    )
        .into_response()
}

async fn settings_save(State(st): State<AppState>, Json(b): Json<Value>) -> Res {
    let url = sv(&b, "webhook_url", "").trim().to_string();
    if !url.is_empty() && !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("Webhook URL must start with http:// or https://".into());
    }
    let mut ths: Vec<i64> = Vec::new();
    for t in b.get("thresholds").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        let n = t.as_i64().or_else(|| t.as_str().and_then(|s| s.trim().parse().ok())).ok_or("Thresholds must be numbers of days")?;
        ths.push(n);
    }
    ths.sort_unstable_by(|a, b| b.cmp(a));
    ths.dedup();
    if ths.len() > 12 || ths.iter().any(|t| !(1..=3650).contains(t)) {
        return Err("Use up to 12 thresholds between 1 and 3650 days".into());
    }
    let s = Settings {
        webhook_url: url,
        chat_id: sv(&b, "chat_id", "").trim().to_string(),
        thresholds: ths,
        enabled: b.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
    };
    let mut d = st.lock();
    d.settings = s.clone();
    st.save(&d)?;
    Ok(Json(json!(s)))
}

async fn settings_test(State(st): State<AppState>) -> Res {
    let s = st.lock().settings.clone();
    tokio::task::spawn_blocking(move || notify("homelab-cert: test notification. Your webhook works.", &s)).await.map_err(es)??;
    Ok(Json(json!({"ok": true})))
}

// ---------- main ----------
async fn shutdown() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
}

#[tokio::main]
async fn main() {
    let dir = PathBuf::from(std::env::var("DATA_DIR").unwrap_or_else(|_| "/data".into()));
    fs::create_dir_all(&dir).expect("cannot create data dir");
    let user = std::env::var("HOMELAB_CERT_USER").unwrap_or_else(|_| "admin".into());
    let pass = std::env::var("HOMELAB_CERT_PASSWORD").unwrap_or_else(|_| "changeme".into());
    if pass == "changeme" {
        eprintln!("WARNING: using default password 'changeme' - set HOMELAB_CERT_PASSWORD");
    }
    let sp = dir.join("secret.key");
    let secret = match fs::read_to_string(&sp) {
        Ok(s) if !s.trim().is_empty() => s.trim().as_bytes().to_vec(),
        _ => {
            let s = hex(&rand::random::<[u8; 32]>());
            write_private(&sp, s.as_bytes()).expect("cannot write secret.key");
            s.into_bytes()
        }
    };
    let path = dir.join("homelab-cert.json");
    let data: Data = match fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).expect("homelab-cert.json is corrupt; fix or remove it"),
        Err(_) => Data::default(),
    };
    let st = AppState(Arc::new(Inner { d: Mutex::new(data), path, user, pass, secret }));

    let st2 = st.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(10)).await;
        loop {
            let s = st2.clone();
            match tokio::task::spawn_blocking(move || check(&s)).await {
                Ok(Err(e)) => eprintln!("expiry check failed: {e}"),
                Err(e) => eprintln!("expiry check crashed: {e}"),
                _ => {}
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });

    let api = Router::new()
        .route("/api/state", get(state))
        .route("/api/root", post(root_create))
        .route("/api/certs", post(cert_create))
        .route("/api/certs/:id", delete(cert_delete))
        .route("/api/certs/:id/renew", post(cert_renew))
        .route("/api/certs/:id/download/:what", get(download))
        .route("/api/settings", put(settings_save))
        .route("/api/settings/test", post(settings_test))
        .layer(from_fn_with_state(st.clone(), auth));
    let app = Router::new()
        .route("/", get(index))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .merge(api)
        .with_state(st);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await.expect("cannot bind port");
    println!("homelab-cert listening on :{port}");
    axum::serve(listener, app).with_graceful_shutdown(shutdown()).await.expect("server error");
}
