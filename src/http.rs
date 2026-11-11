//! Epicbox over HTTPS: the same mailboxes, messages and signatures as the websocket protocol,
//! as plain JSON requests. Served by the canister itself through the ICP HTTP gateway (use the
//! `raw` domain: reads are answered by one node and are not certified; every message carries its
//! sender's signature, which the client checks).
//!
//! - `GET  /v1/info`  what this service accepts
//! - `POST /v1/post`  `{from, to, str, signature}`, the Epicbox `PostSlate` unchanged
//! - `POST /v1/pull`  `{mailboxes: [{address, challenge, signature}], limit}`; the client makes its
//!   own challenge, `ebh-<unix seconds>-<random hex>`, and signs it as it would sign `Subscribe`
//! - `POST /v1/made`  `{address, acks: [{id, signature}]}`, each signature over the id, as `Made`
//! - `GET  /stats`    counters
//!
//! Reads run as queries (fast, free); `post` and `made` are passed on as updates (consensus).

use serde::Deserialize;
use serde_json::{Value, json};

use crate::store::{
    CHALLENGE_WINDOW_S, MAX_PULL, MAX_STR, PostSlate, SignedMade, SignedPull, State, TTL_NS,
};

pub const PROTOCOL: &str = "epicbox-https/0.1";
pub const MAX_MAILBOXES_PER_PULL: usize = 64;
/// Posts per sender key per hour over HTTPS, where anyone may post and the canister pays.
pub const HTTP_POSTS_PER_HOUR: u32 = 60;

pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub body: &'a [u8],
}

pub struct Response {
    pub status: u16,
    pub body: String,
    /// Ask the gateway to send the same request again as an update call.
    pub upgrade: bool,
}

impl Response {
    fn json(status: u16, value: Value) -> Self {
        Response { status, body: value.to_string(), upgrade: false }
    }
    fn error(status: u16, message: &str) -> Self {
        Self::json(status, json!({ "error": message }))
    }
    fn upgrade() -> Self {
        Response { status: 200, body: String::new(), upgrade: true }
    }
}

pub fn headers() -> Vec<(String, String)> {
    vec![
        ("content-type".into(), "application/json".into()),
        ("cache-control".into(), "no-store".into()),
        ("access-control-allow-origin".into(), "*".into()),
        ("access-control-allow-methods".into(), "GET, POST, OPTIONS".into()),
        ("access-control-allow-headers".into(), "content-type".into()),
    ]
}

fn path(url: &str) -> &str {
    url.split('?').next().unwrap_or_default()
}

#[derive(Deserialize)]
struct PullBody {
    mailboxes: Vec<SignedPull>,
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct Ack {
    id: String,
    signature: String,
}

#[derive(Deserialize)]
struct MadeBody {
    address: String,
    acks: Vec<Ack>,
}

#[derive(Deserialize)]
struct PostBody {
    from: String,
    to: String,
    str: String,
    signature: String,
}

/// The query half: reads are answered here, writes ask to be upgraded.
pub fn query(state: &State, req: &Request, now_ns: u64) -> Response {
    match (req.method, path(req.url)) {
        ("OPTIONS", _) => Response { status: 204, body: String::new(), upgrade: false },
        ("GET", "/v1/info") => Response::json(200, info(state)),
        ("GET", "/stats") | ("GET", "/stats.json") => Response::json(200, stats(state, now_ns)),
        ("POST", "/v1/pull") => pull(state, req.body, now_ns),
        ("POST", "/v1/post") | ("POST", "/v1/made") => Response::upgrade(),
        _ => Response::error(404, "not found"),
    }
}

/// The update half, for the requests `query` upgraded.
pub fn update(state: &mut State, req: &Request, now_ns: u64) -> Response {
    match (req.method, path(req.url)) {
        ("POST", "/v1/post") => post(state, req.body, now_ns),
        ("POST", "/v1/made") => made(state, req.body, now_ns),
        _ => Response::error(404, "not found"),
    }
}

fn info(state: &State) -> Value {
    json!({
        "protocol": PROTOCOL,
        "epicbox_protocol": "3.0.0",
        "domains": state.local_domains.iter().collect::<Vec<_>>(),
        "challenge": format!("ebh-<unix seconds>-<random hex>, signed like Subscribe, accepted for {} s", CHALLENGE_WINDOW_S),
        "retention_s": TTL_NS / 1_000_000_000,
        "max_str_bytes": MAX_STR,
        "max_mailboxes_per_pull": MAX_MAILBOXES_PER_PULL,
        "max_messages_per_mailbox": MAX_PULL,
        "posts_per_sender_per_hour": HTTP_POSTS_PER_HOUR,
    })
}

pub fn stats(state: &State, now_ns: u64) -> Value {
    let v = state.stats_view();
    json!({
        "time_ns": now_ns,
        "waiting": v.messages - v.outbound,
        "outbound": v.outbound,
        "mailboxes": v.queues,
        "bytes": v.bytes,
        "posted": v.counters.posted,
        "delivered": v.counters.made,
        "forwarded": v.counters.forwarded,
        "forward_failed": v.counters.forward_failed,
        "expired": v.counters.expired,
        "refused": v.counters.refused,
        "duplicates": state.counters_extra.as_ref().map_or(0, |c| c.duplicates),
        "local_domains": v.local_domains,
    })
}

fn pull(state: &State, body: &[u8], now_ns: u64) -> Response {
    let Ok(req) = serde_json::from_slice::<PullBody>(body) else {
        return Response::error(400, "body must be {mailboxes: [{address, challenge, signature}], limit}");
    };
    if req.mailboxes.is_empty() || req.mailboxes.len() > MAX_MAILBOXES_PER_PULL {
        return Response::error(400, "1 to 64 mailboxes per pull");
    }
    let limit = req.limit.unwrap_or(MAX_PULL);
    let results: Vec<Value> = req
        .mailboxes
        .iter()
        .map(|auth| match state.pull_many_signed(auth, limit, now_ns) {
            Ok(list) => json!({
                "address": auth.address,
                "messages": list.iter().map(|d| json!({
                    "id": d.epicboxmsgid,
                    "from": d.from,
                    "str": d.str,
                    "signature": d.signature,
                    "posted_ns": d.posted_ns,
                })).collect::<Vec<_>>(),
            }),
            Err(e) => json!({ "address": auth.address, "error": e }),
        })
        .collect();
    Response::json(200, json!({ "mailboxes": results }))
}

fn post(state: &mut State, body: &[u8], now_ns: u64) -> Response {
    let Ok(b) = serde_json::from_slice::<PostBody>(body) else {
        return Response::error(400, "body must be {from, to, str, signature}");
    };
    let slate = PostSlate { from: b.from, to: b.to, str: b.str, signature: b.signature };
    match state.post_http(slate, now_ns) {
        Ok(id) => Response::json(200, json!({ "ok": true, "id": id })),
        Err(e) if e.starts_with("Too many") || e.contains("full") => Response::error(429, &e),
        Err(e) => Response::error(400, &e),
    }
}

fn made(state: &mut State, body: &[u8], now_ns: u64) -> Response {
    let Ok(b) = serde_json::from_slice::<MadeBody>(body) else {
        return Response::error(400, "body must be {address, acks: [{id, signature}]}");
    };
    let mut done = 0u32;
    let mut refused = 0u32;
    for ack in b.acks.iter().take(MAX_PULL as usize) {
        let made = SignedMade { address: b.address.clone(), epicboxmsgid: ack.id.clone(), signature: ack.signature.clone() };
        let before = state.counters.made;
        match state.made_signed(&made, now_ns) {
            Ok(()) if state.counters.made > before => done += 1,
            Ok(()) => {}
            Err(_) => refused += 1,
        }
    }
    Response::json(200, json!({ "removed": done, "refused": refused }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::Signer;
    use k256::ecdsa::{Signature, SigningKey};
    use sha2::{Digest, Sha256};

    const T0: u64 = 1_800_000_000 * 1_000_000_000;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32].into()).unwrap()
    }
    fn address(k: &SigningKey) -> String {
        let mut p = vec![0x01, 0x00];
        p.extend_from_slice(k.verifying_key().to_encoded_point(true).as_bytes());
        let c = Sha256::digest(Sha256::digest(&p));
        p.extend_from_slice(&c[..4]);
        bs58::encode(p).into_string()
    }
    fn sign(k: &SigningKey, text: &str) -> String {
        let s: Signature = k.sign(text.as_bytes());
        s.normalize_s().unwrap_or(s).to_der().as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }
    fn req<'a>(method: &'a str, url: &'a str, body: &'a [u8]) -> Request<'a> {
        Request { method, url, body }
    }
    fn json_of(r: &Response) -> Value {
        serde_json::from_str(&r.body).unwrap()
    }

    #[test]
    fn post_pull_made_over_https() {
        let (alice, bob) = (key(1), key(2));
        let mut s = State::default();
        s.local_domains.insert("icpepicbox.btlabs.uk:443".into());
        let str = format!(r#"{{"destination":{{"public_key":"{}","domain":"icpepicbox.btlabs.uk","port":443}},"encrypted_message":"00","salt":"01","nonce":"02"}}"#, address(&bob));
        let body = json!({"from": format!("{}@icpepicbox.btlabs.uk", address(&alice)), "to": format!("{}@icpepicbox.btlabs.uk", address(&bob)), "str": str, "signature": sign(&alice, &str)}).to_string();

        // The query half asks for an upgrade; the update half posts.
        assert!(query(&s, &req("POST", "/v1/post", body.as_bytes()), T0).upgrade);
        let r = update(&mut s, &req("POST", "/v1/post", body.as_bytes()), T0);
        assert_eq!(r.status, 200, "{}", r.body);
        let id = json_of(&r)["id"].as_str().unwrap().to_string();
        // Posting the same thing again gives the same id.
        assert_eq!(json_of(&update(&mut s, &req("POST", "/v1/post", body.as_bytes()), T0))["id"], id.as_str());

        // Bob pulls Alice's mailbox and his own in one request, with his own challenge.
        let challenge = format!("ebh-{}-9f1c", T0 / 1_000_000_000);
        let pull = json!({"mailboxes": [
            {"address": address(&bob), "challenge": challenge, "signature": sign(&bob, &challenge)},
            {"address": address(&alice), "challenge": challenge, "signature": sign(&bob, &challenge)},
        ]}).to_string();
        let r = query(&s, &req("POST", "/v1/pull", pull.as_bytes()), T0);
        assert!(!r.upgrade);
        let v = json_of(&r);
        assert_eq!(v["mailboxes"][0]["messages"][0]["id"], id.as_str());
        assert_eq!(v["mailboxes"][1]["error"], "InvalidSignature");

        let made = json!({"address": address(&bob), "acks": [{"id": id, "signature": sign(&bob, &id)}]}).to_string();
        let r = update(&mut s, &req("POST", "/v1/made", made.as_bytes()), T0);
        assert_eq!(json_of(&r)["removed"], 1);
        let v = json_of(&query(&s, &req("POST", "/v1/pull", pull.as_bytes()), T0));
        assert_eq!(v["mailboxes"][0]["messages"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn https_posts_are_rate_limited_per_sender() {
        let (alice, bob) = (key(1), key(2));
        let mut s = State::default();
        let mut last = 0;
        for i in 0..(HTTP_POSTS_PER_HOUR + 1) {
            let str = format!(r#"{{"destination":{{"public_key":"{}","domain":"icpepicbox.btlabs.uk","port":443}},"encrypted_message":"{i:04x}","salt":"01","nonce":"02"}}"#, address(&bob));
            let body = json!({"from": address(&alice), "to": address(&bob), "str": str, "signature": sign(&alice, &str)}).to_string();
            last = update(&mut s, &req("POST", "/v1/post", body.as_bytes()), T0).status;
        }
        // The per-mailbox caps stop it first (20 pending per sender), the hourly limit after.
        assert_eq!(last, 429);
    }

    #[test]
    fn info_cors_and_unknown_paths() {
        let s = State::default();
        assert_eq!(query(&s, &req("OPTIONS", "/v1/post", b""), T0).status, 204);
        assert_eq!(json_of(&query(&s, &req("GET", "/v1/info", b""), T0))["protocol"], PROTOCOL);
        assert_eq!(query(&s, &req("GET", "/nope", b""), T0).status, 404);
        assert_eq!(query(&s, &req("POST", "/v1/pull", b"{}"), T0).status, 400);
    }
}
