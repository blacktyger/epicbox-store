//! Epicbox store: the queues of an Epicbox relay, kept in an ICP canister.
//!
//! Front-ends speak the Epicbox websocket protocol (3.0.0) to wallets and turn each frame into a
//! call here; other canisters call it directly, and any HTTPS client can use `/v1/` (`http.rs`).
//! The canister checks every signature itself, so a front-end can neither forge a message nor
//! read a queue without the wallet's signature over a fresh challenge.
//!
//! Semantics follow Epicbox relays: a post is accepted when `signature` verifies over `str` for
//! the key in `from`; the queue is the key in `str.destination.public_key`; messages wait until
//! `Made` or 7 days.

pub mod http;
pub mod store;

use std::cell::RefCell;

use candid::Principal;
use store::{
    Delivery, ForwardFailure, Outbound, OwnerPull, PostSlate, SignedMade, SignedPull, State, StatsView,
};

fn require_poster() -> Result<(), String> {
    let who = caller();
    if ic_cdk::api::is_controller(&who) || STATE.with(|s| s.borrow().posters.contains(&who)) {
        Ok(())
    } else {
        Err("Unauthorized.".into())
    }
}

/// Messages for other relays, for a front-end to deliver. Front-ends only.
#[ic_cdk::query]
fn pull_outbound(limit: u32) -> Result<Vec<Outbound>, String> {
    require_poster()?;
    Ok(STATE.with(|s| s.borrow().pull_outbound(limit, now_ns())))
}

/// What a front-end delivered and what failed. Returns (removed, dropped after too many tries).
#[ic_cdk::update]
fn outbound_done(delivered: Vec<String>, failed: Vec<ForwardFailure>) -> Result<(u32, u32), String> {
    require_poster()?;
    Ok(STATE.with(|s| s.borrow_mut().outbound_done(&delivered, &failed, now_ns())))
}

/// The `domain:port` names this store answers for; everything else is forwarded.
#[ic_cdk::update]
fn set_local_domains(domains: Vec<String>) -> Result<(), String> {
    require_controller()?;
    STATE.with(|s| {
        s.borrow_mut().local_domains = domains
            .iter()
            .map(|d| match d.rsplit_once(':') {
                Some((host, port)) => store::relay_name(host, port.parse().ok()),
                None => store::relay_name(d, None),
            })
            .collect();
    });
    Ok(())
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

fn now_ns() -> u64 {
    ic_cdk::api::time()
}

fn caller() -> Principal {
    ic_cdk::api::msg_caller()
}

fn require_controller() -> Result<(), String> {
    if ic_cdk::api::is_controller(&caller()) { Ok(()) } else { Err("controllers only".into()) }
}

/// Posts a message. Callers: front-ends and canisters on the poster list, or a controller.
#[ic_cdk::update]
fn post(slate: PostSlate) -> Result<String, String> {
    let who = caller();
    let allowed = ic_cdk::api::is_controller(&who) || STATE.with(|s| s.borrow().posters.contains(&who));
    if !allowed {
        return Err("Unauthorized poster.".into());
    }
    STATE.with(|s| s.borrow_mut().post(slate, who, now_ns()))
}

/// The oldest pending message for an address, for a wallet that signed a fresh challenge
/// (`eicp-<unix seconds>-<random>`, at most 20 minutes old).
#[ic_cdk::query]
fn pull(auth: SignedPull) -> Result<Option<Delivery>, String> {
    STATE.with(|s| s.borrow().pull_signed(&auth, now_ns()))
}

/// Up to `limit` pending messages for each of several addresses at once, each with its own
/// signature: the one-connection-per-mailbox limit of the websocket protocol does not apply here.
#[ic_cdk::query]
fn pull_many(auths: Vec<SignedPull>, limit: u32) -> Vec<Result<Vec<Delivery>, String>> {
    STATE.with(|s| {
        let s = s.borrow();
        auths.iter().take(64).map(|a| s.pull_many_signed(a, limit, now_ns())).collect()
    })
}

/// Acknowledges a message with the address key's signature over its id, as `Made` does.
#[ic_cdk::update]
fn made(made: SignedMade) -> Result<(), String> {
    STATE.with(|s| s.borrow_mut().made_signed(&made, now_ns()))
}

/// Binds an address to the calling principal, proven by the address key's signature over
/// `epicbox-icp claim <principal>`. The owner may then pull and acknowledge without signing.
#[ic_cdk::update]
fn claim(address: String, signature: String) -> Result<(), String> {
    let who = caller();
    STATE.with(|s| s.borrow_mut().claim(&address, &signature, who))
}

#[ic_cdk::query]
fn pull_owned(req: OwnerPull) -> Result<Vec<Delivery>, String> {
    let who = caller();
    STATE.with(|s| s.borrow().pull_owned(&req, who, now_ns()))
}

#[ic_cdk::update]
fn made_owned(address: String, ids: Vec<String>) -> Result<u32, String> {
    let who = caller();
    STATE.with(|s| s.borrow_mut().made_owned(&address, &ids, who, now_ns()))
}

#[ic_cdk::query]
fn stats() -> StatsView {
    STATE.with(|s| s.borrow().stats_view())
}

#[derive(candid::CandidType, serde::Deserialize)]
struct HttpRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(candid::CandidType)]
struct HttpResponse {
    status_code: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    upgrade: Option<bool>,
}

fn respond(r: http::Response) -> HttpResponse {
    HttpResponse {
        status_code: r.status,
        headers: http::headers(),
        body: r.body.into_bytes(),
        upgrade: r.upgrade.then_some(true),
    }
}

/// Epicbox over HTTPS (see `http.rs`) and `GET /stats` for the relay's web page. Use the raw
/// gateway domain: these answers are not certified.
#[ic_cdk::query]
fn http_request(req: HttpRequest) -> HttpResponse {
    let path = req.url.split('?').next().unwrap_or_default();
    if req.method == "GET" && (path == "/stats" || path == "/stats.json") {
        let mut v = STATE.with(|s| http::stats(&s.borrow(), now_ns()));
        v["canister"] = ic_cdk::api::canister_self().to_text().into();
        v["cycles"] = ic_cdk::api::canister_cycle_balance().to_string().into();
        return respond(http::Response { status: 200, body: v.to_string(), upgrade: false });
    }
    let r = http::Request { method: &req.method, url: &req.url, body: &req.body };
    respond(STATE.with(|s| http::query(&s.borrow(), &r, now_ns())))
}

#[ic_cdk::update]
fn http_request_update(req: HttpRequest) -> HttpResponse {
    let r = http::Request { method: &req.method, url: &req.url, body: &req.body };
    respond(STATE.with(|s| http::update(&mut s.borrow_mut(), &r, now_ns())))
}

#[ic_cdk::update]
fn add_poster(p: Principal) -> Result<(), String> {
    require_controller()?;
    STATE.with(|s| s.borrow_mut().posters.insert(p));
    Ok(())
}

#[ic_cdk::update]
fn remove_poster(p: Principal) -> Result<(), String> {
    require_controller()?;
    STATE.with(|s| s.borrow_mut().posters.remove(&p));
    Ok(())
}

#[ic_cdk::query]
fn posters() -> Vec<Principal> {
    STATE.with(|s| s.borrow().posters.iter().copied().collect())
}

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    STATE.with(|s| ic_cdk::storage::stable_save((&*s.borrow(),)).expect("save state"));
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    let (state,): (State,) = ic_cdk::storage::stable_restore().expect("restore state");
    STATE.with(|s| *s.borrow_mut() = state);
}

ic_cdk::export_candid!();
