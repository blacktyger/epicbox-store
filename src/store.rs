//! The store's logic, free of ic-cdk so it runs in native tests.

use std::collections::{BTreeMap, BTreeSet};

use candid::{CandidType, Deserialize, Principal};
use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};

/// Messages live 7 days, the retention Epicbox relays use.
pub const TTL_NS: u64 = 7 * 24 * 3600 * 1_000_000_000;
/// How old a challenge may be when a pull presents it.
pub const CHALLENGE_WINDOW_S: u64 = 20 * 60;
/// Challenges are `eicp-<unix seconds>-<16 hex>`: wallets accept only `[A-Za-z0-9_-]`, at most 64 bytes.
pub const CHALLENGE_PREFIX: &str = "eicp-";
pub const CLAIM_PREFIX: &str = "epicbox-icp claim ";
pub const MAX_STR: usize = 128 * 1024;
pub const MAX_PENDING_PER_QUEUE: usize = 200;
pub const MAX_PENDING_PER_SENDER_AND_QUEUE: usize = 20;
pub const MAX_MESSAGES: usize = 50_000;
pub const MAX_PULL: u32 = 50;
/// A message for another relay is tried this many times, with growing pauses, then dropped.
pub const MAX_FORWARD_ATTEMPTS: u32 = 8;
const FORWARD_BACKOFF_NS: u64 = 15 * 1_000_000_000;

const MAINNET: [u8; 2] = [0x01, 0x00];
const FLOONET: [u8; 2] = [0x01, 0x88];

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct PostSlate {
    pub from: String,
    pub to: String,
    pub str: String,
    pub signature: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct SignedPull {
    /// The base58 key, with or without `@domain`.
    pub address: String,
    pub challenge: String,
    /// DER hex ECDSA over SHA-256 of `challenge`, as `Subscribe` sends it.
    pub signature: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct SignedMade {
    pub address: String,
    pub epicboxmsgid: String,
    pub signature: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct OwnerPull {
    pub address: String,
    pub limit: u32,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct Delivery {
    pub epicboxmsgid: String,
    pub from: String,
    pub str: String,
    pub signature: String,
    pub posted_ns: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Stored {
    pub queue: String,
    pub sender: String,
    pub from: String,
    pub to: String,
    pub str: String,
    pub signature: String,
    pub posted_ns: u64,
    pub poster: Principal,
    /// `Some("domain:port")` when the message is for another relay and waits to be forwarded.
    pub relay: Option<String>,
    pub attempts: u32,
    pub retry_after_ns: u64,
}

/// A message the front-ends deliver to another relay, unchanged, as the public relay does.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct Outbound {
    pub id: String,
    pub relay: String,
    pub from: String,
    pub to: String,
    pub str: String,
    pub signature: String,
    pub attempts: u32,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct ForwardFailure {
    pub id: String,
    pub error: String,
}

#[derive(CandidType, Deserialize, Clone, Debug, Default)]
pub struct Counters {
    pub posted: u64,
    pub made: u64,
    pub expired: u64,
    pub refused: u64,
    pub forwarded: u64,
    pub forward_failed: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct StatsView {
    pub messages: u64,
    pub queues: u64,
    pub bytes: u64,
    pub owners: u64,
    pub posters: u64,
    pub outbound: u64,
    pub local_domains: Vec<String>,
    pub counters: Counters,
}

#[derive(CandidType, Deserialize, Default)]
pub struct State {
    pub next_id: u64,
    pub messages: BTreeMap<u64, Stored>,
    pub queues: BTreeMap<String, BTreeSet<u64>>,
    pub posters: BTreeSet<Principal>,
    pub owners: BTreeMap<String, Principal>,
    pub counters: Counters,
    /// The `domain:port` names this store answers for. A post whose `str.destination` names
    /// another is forwarded there. Empty: everything is kept here.
    pub local_domains: BTreeSet<String>,
    pub outbound: BTreeSet<u64>,
    /// Posts already taken, by digest of signature and `str`, with when they came. A post that
    /// arrives again, from a retry or from more than one route, gets the first id back instead of
    /// a second copy. Kept for the retention period.
    pub seen: Option<BTreeMap<String, (u64, u64)>>,
    pub counters_extra: Option<CountersExtra>,
    /// HTTPS posts per sender key in the current hour: (window start, count).
    pub http_rate: Option<BTreeMap<String, (u64, u32)>>,
    /// Principals allowed the routine, additive settings: adding a poster or a local domain.
    /// Removing either, and changing this list, stay with the controllers.
    pub operators: Option<BTreeSet<Principal>>,
}

#[derive(CandidType, Deserialize, Clone, Debug, Default)]
pub struct CountersExtra {
    pub duplicates: u64,
}

fn post_digest(slate: &PostSlate) -> String {
    let mut h = Sha256::new();
    h.update(slate.signature.as_bytes());
    h.update([0u8]);
    h.update(slate.str.as_bytes());
    h.finalize()[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// `domain:port`, lowercase, port 443 when absent, as the public relay compares them.
pub fn relay_name(domain: &str, port: Option<u64>) -> String {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    format!("{domain}:{}", port.unwrap_or(443))
}

/// A decoded Epicbox key: its canonical base58 text and the compressed public key.
#[derive(Clone, Debug, PartialEq)]
pub struct Key {
    pub text: String,
    pub sec1: [u8; 33],
}

/// Parses `[epicbox://]<base58 key>[@domain[:port]]`. Mainnet and floonet keys are both accepted;
/// the version bytes stay part of the queue name, so the two never share a queue.
pub fn decode_key(address: &str) -> Result<Key, String> {
    let bare = address.strip_prefix("epicbox://").unwrap_or(address);
    let key_text = bare.split('@').next().unwrap_or_default();
    let raw = bs58::decode(key_text).into_vec().map_err(|_| "Wrong address format.".to_string())?;
    if raw.len() != 2 + 33 + 4 {
        return Err("Wrong address format.".into());
    }
    let (payload, check) = raw.split_at(35);
    let digest = Sha256::digest(Sha256::digest(payload));
    if digest[..4] != *check {
        return Err("Wrong address format.".into());
    }
    if payload[..2] != MAINNET && payload[..2] != FLOONET {
        return Err("Wrong address format.".into());
    }
    let mut sec1 = [0u8; 33];
    sec1.copy_from_slice(&payload[2..]);
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| "Wrong address format.".to_string())?;
    Ok(Key { text: bs58::encode(&raw).into_string(), sec1 })
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || text.len() > 2 * 80 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// ECDSA over secp256k1 of SHA-256 of the UTF-8 text, DER hex. High-S signatures are refused,
/// as libsecp256k1 (and so the public relay and every wallet) refuses them.
pub fn signed_by(key: &Key, text: &str, signature_hex: &str) -> bool {
    let Some(der) = hex_decode(signature_hex) else { return false };
    let Ok(signature) = Signature::from_der(&der) else { return false };
    if signature.normalize_s().is_some() {
        return false;
    }
    let Ok(verifying) = VerifyingKey::from_sec1_bytes(&key.sec1) else { return false };
    verifying.verify(text.as_bytes(), &signature).is_ok()
}

/// Where a post goes: the key in `str.destination.public_key` and the relay named by
/// `str.destination.domain` and `port`, as the public relay routes it.
fn destination(str: &str) -> Result<(Key, String), String> {
    let value: serde_json::Value =
        serde_json::from_str(str).map_err(|_| "Error parsing message string.".to_string())?;
    let dest = value.get("destination").ok_or_else(|| "Error parsing message string.".to_string())?;
    let key = dest
        .get("public_key")
        .and_then(|k| k.as_str())
        .ok_or_else(|| "Error parsing message string.".to_string())?;
    let domain = dest.get("domain").and_then(|d| d.as_str()).unwrap_or_default();
    let port = dest.get("port").and_then(|p| p.as_u64());
    Ok((decode_key(key)?, relay_name(domain, port)))
}

fn challenge_fresh(challenge: &str, now_ns: u64) -> bool {
    // `eicp-` from the websocket front-end, `ebh-` from Epicbox-over-HTTPS clients (the same spec as
    // the epic-relay /v1 API).
    let Some(rest) = challenge.strip_prefix(CHALLENGE_PREFIX).or_else(|| challenge.strip_prefix("ebh-")) else {
        return false;
    };
    if challenge.len() > 64 {
        return false;
    }
    let Some(secs) = rest.split('-').next().and_then(|s| s.parse::<u64>().ok()) else {
        return false;
    };
    let now = now_ns / 1_000_000_000;
    secs <= now + 60 && now.saturating_sub(secs) <= CHALLENGE_WINDOW_S
}

fn id_text(id: u64) -> String {
    format!("icp{id}")
}

fn id_parse(text: &str) -> Option<u64> {
    text.strip_prefix("icp")?.parse().ok()
}

impl State {
    fn delivery(&self, id: u64) -> Option<Delivery> {
        self.messages.get(&id).map(|m| Delivery {
            epicboxmsgid: id_text(id),
            from: m.from.clone(),
            str: m.str.clone(),
            signature: m.signature.clone(),
            posted_ns: m.posted_ns,
        })
    }

    fn pending(&self, queue: &str, limit: u32, now_ns: u64) -> Vec<Delivery> {
        self.queues
            .get(queue)
            .into_iter()
            .flatten()
            .filter(|id| self.messages.get(id).is_some_and(|m| now_ns.saturating_sub(m.posted_ns) < TTL_NS))
            .take(limit.min(MAX_PULL) as usize)
            .filter_map(|id| self.delivery(*id))
            .collect()
    }

    fn remove(&mut self, id: u64) -> bool {
        let Some(m) = self.messages.remove(&id) else { return false };
        self.outbound.remove(&id);
        if let Some(q) = self.queues.get_mut(&m.queue) {
            q.remove(&id);
            if q.is_empty() {
                self.queues.remove(&m.queue);
            }
        }
        true
    }

    /// Drops expired messages. Ids grow with time, so the oldest are first.
    pub fn purge(&mut self, now_ns: u64) {
        let expired: Vec<u64> = self
            .messages
            .iter()
            .take_while(|(_, m)| now_ns.saturating_sub(m.posted_ns) >= TTL_NS)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.remove(id);
            self.counters.expired += 1;
        }
        if let Some(seen) = self.seen.as_mut() {
            seen.retain(|_, (_, at)| now_ns.saturating_sub(*at) < TTL_NS);
        }
    }

    /// A post over HTTPS, where anyone may post and the canister pays: limited per sender key.
    pub fn post_http(&mut self, slate: PostSlate, now_ns: u64) -> Result<String, String> {
        const HOUR_NS: u64 = 3600 * 1_000_000_000;
        if let Ok(sender) = decode_key(&slate.from) {
            let rate = self.http_rate.get_or_insert_with(BTreeMap::new);
            rate.retain(|_, (start, _)| now_ns.saturating_sub(*start) < HOUR_NS);
            let entry = rate.entry(sender.text).or_insert((now_ns, 0));
            if entry.1 >= crate::http::HTTP_POSTS_PER_HOUR {
                self.counters.refused += 1;
                return Err("Too many posts from this sender; try again later.".into());
            }
            entry.1 += 1;
        }
        self.post(slate, Principal::anonymous(), now_ns)
    }

    pub fn post(&mut self, slate: PostSlate, poster: Principal, now_ns: u64) -> Result<String, String> {
        self.purge(now_ns);
        let result = self.try_post(slate, poster, now_ns);
        if result.is_err() {
            self.counters.refused += 1;
        }
        result
    }

    fn try_post(&mut self, slate: PostSlate, poster: Principal, now_ns: u64) -> Result<String, String> {
        if slate.str.len() > MAX_STR {
            return Err("Message too large.".into());
        }
        let sender = decode_key(&slate.from)?;
        decode_key(&slate.to)?;
        if !signed_by(&sender, &slate.str, &slate.signature) {
            return Err("Error postslate signature.".into());
        }
        let digest = post_digest(&slate);
        if let Some(&(id, _)) = self.seen.as_ref().and_then(|seen| seen.get(&digest)) {
            self.counters_extra.get_or_insert_with(CountersExtra::default).duplicates += 1;
            return Ok(id_text(id));
        }
        let (dest, relay) = destination(&slate.str)?;
        let queue = dest.text;
        let local = self.local_domains.is_empty() || self.local_domains.contains(&relay);
        if !local && relay.starts_with(':') {
            return Err("Error parsing message string.".into());
        }
        let ids = self.queues.get(&queue);
        let pending = ids.map_or(0, BTreeSet::len);
        if pending >= MAX_PENDING_PER_QUEUE {
            return Err("Mailbox full.".into());
        }
        let from_sender = ids
            .into_iter()
            .flatten()
            .filter(|id| self.messages.get(id).is_some_and(|m| m.sender == sender.text))
            .count();
        if from_sender >= MAX_PENDING_PER_SENDER_AND_QUEUE {
            return Err("Too many pending messages from this sender.".into());
        }
        if self.messages.len() >= MAX_MESSAGES {
            return Err("Store full.".into());
        }
        self.next_id += 1;
        let id = self.next_id;
        self.messages.insert(
            id,
            Stored {
                queue: queue.clone(),
                sender: sender.text,
                from: slate.from,
                to: slate.to,
                str: slate.str,
                signature: slate.signature,
                posted_ns: now_ns,
                poster,
                relay: (!local).then(|| relay.clone()),
                attempts: 0,
                retry_after_ns: 0,
            },
        );
        if local {
            self.queues.entry(queue).or_default().insert(id);
        } else {
            self.outbound.insert(id);
        }
        self.seen.get_or_insert_with(BTreeMap::new).insert(digest, (id, now_ns));
        self.counters.posted += 1;
        Ok(id_text(id))
    }

    fn signed_key(&self, auth: &SignedPull, now_ns: u64) -> Result<Key, String> {
        let key = decode_key(&auth.address)?;
        if !challenge_fresh(&auth.challenge, now_ns) {
            return Err("InvalidChallenge".into());
        }
        if !signed_by(&key, &auth.challenge, &auth.signature) {
            return Err("InvalidSignature".into());
        }
        Ok(key)
    }

    pub fn pull_signed(&self, auth: &SignedPull, now_ns: u64) -> Result<Option<Delivery>, String> {
        let key = self.signed_key(auth, now_ns)?;
        Ok(self.pending(&key.text, 1, now_ns).into_iter().next())
    }

    pub fn pull_many_signed(&self, auth: &SignedPull, limit: u32, now_ns: u64) -> Result<Vec<Delivery>, String> {
        let key = self.signed_key(auth, now_ns)?;
        Ok(self.pending(&key.text, limit, now_ns))
    }

    pub fn made_signed(&mut self, made: &SignedMade, now_ns: u64) -> Result<(), String> {
        self.purge(now_ns);
        let key = decode_key(&made.address)?;
        if !signed_by(&key, &made.epicboxmsgid, &made.signature) {
            return Err("InvalidSignature".into());
        }
        let id = id_parse(&made.epicboxmsgid).ok_or("Unknown message id.")?;
        // Acknowledging something already gone is not an error: deliveries can repeat.
        if self.messages.get(&id).is_some_and(|m| m.queue == key.text) {
            self.remove(id);
            self.counters.made += 1;
        }
        Ok(())
    }

    pub fn claim(&mut self, address: &str, signature: &str, owner: Principal) -> Result<(), String> {
        let key = decode_key(address)?;
        let text = format!("{CLAIM_PREFIX}{}", owner.to_text());
        if !signed_by(&key, &text, signature) {
            return Err("InvalidSignature".into());
        }
        self.owners.insert(key.text, owner);
        Ok(())
    }

    fn owned_key(&self, address: &str, caller: Principal) -> Result<Key, String> {
        let key = decode_key(address)?;
        if self.owners.get(&key.text) != Some(&caller) {
            return Err("Not the owner of this address.".into());
        }
        Ok(key)
    }

    pub fn pull_owned(&self, req: &OwnerPull, caller: Principal, now_ns: u64) -> Result<Vec<Delivery>, String> {
        let key = self.owned_key(&req.address, caller)?;
        Ok(self.pending(&key.text, req.limit, now_ns))
    }

    pub fn made_owned(&mut self, address: &str, ids: &[String], caller: Principal, now_ns: u64) -> Result<u32, String> {
        self.purge(now_ns);
        let key = self.owned_key(address, caller)?;
        let mut done = 0;
        for id in ids.iter().filter_map(|t| id_parse(t)) {
            if self.messages.get(&id).is_some_and(|m| m.queue == key.text) {
                self.remove(id);
                self.counters.made += 1;
                done += 1;
            }
        }
        Ok(done)
    }

    /// Messages due for forwarding to another relay, oldest first.
    pub fn pull_outbound(&self, limit: u32, now_ns: u64) -> Vec<Outbound> {
        self.outbound
            .iter()
            .filter_map(|id| self.messages.get(id).map(|m| (id, m)))
            .filter(|(_, m)| m.retry_after_ns <= now_ns && now_ns.saturating_sub(m.posted_ns) < TTL_NS)
            .take(limit.min(MAX_PULL) as usize)
            .map(|(id, m)| Outbound {
                id: id_text(*id),
                relay: m.relay.clone().unwrap_or_default(),
                from: m.from.clone(),
                to: m.to.clone(),
                str: m.str.clone(),
                signature: m.signature.clone(),
                attempts: m.attempts,
            })
            .collect()
    }

    /// Records what a front-end forwarded. Returns (removed, dropped after too many attempts).
    pub fn outbound_done(&mut self, delivered: &[String], failed: &[ForwardFailure], now_ns: u64) -> (u32, u32) {
        let (mut removed, mut dropped) = (0, 0);
        for id in delivered.iter().filter_map(|t| id_parse(t)) {
            if self.outbound.contains(&id) && self.remove(id) {
                self.counters.forwarded += 1;
                removed += 1;
            }
        }
        for f in failed {
            let Some(id) = id_parse(&f.id) else { continue };
            if !self.outbound.contains(&id) {
                continue;
            }
            let give_up = match self.messages.get_mut(&id) {
                Some(m) => {
                    m.attempts += 1;
                    m.retry_after_ns = now_ns + FORWARD_BACKOFF_NS * (1u64 << m.attempts.min(10));
                    m.attempts >= MAX_FORWARD_ATTEMPTS
                }
                None => false,
            };
            if give_up && self.remove(id) {
                self.counters.forward_failed += 1;
                dropped += 1;
            }
        }
        (removed, dropped)
    }

    /// Whether `who` may make an additive settings change: a controller or an operator.
    pub fn may_operate(&self, who: &Principal, is_controller: bool) -> bool {
        is_controller || self.operators.as_ref().is_some_and(|o| o.contains(who))
    }

    /// Adds `domain` (as `host` or `host:port`) to the domains this store answers for.
    pub fn add_local_domain(&mut self, domain: &str) -> String {
        let name = match domain.rsplit_once(':') {
            Some((host, port)) => relay_name(host, port.parse().ok()),
            None => relay_name(domain, None),
        };
        self.local_domains.insert(name.clone());
        name
    }

    pub fn stats_view(&self) -> StatsView {
        StatsView {
            messages: self.messages.len() as u64,
            queues: self.queues.len() as u64,
            bytes: self.messages.values().map(|m| m.str.len() as u64).sum(),
            owners: self.owners.len() as u64,
            posters: self.posters.len() as u64,
            outbound: self.outbound.len() as u64,
            local_domains: self.local_domains.iter().cloned().collect(),
            counters: self.counters.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use k256::ecdsa::signature::Signer;

    const T0: u64 = 1_800_000_000 * 1_000_000_000;

    fn signing(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32].into()).unwrap()
    }

    fn address(key: &SigningKey) -> String {
        let point = key.verifying_key().to_encoded_point(true);
        let mut payload = MAINNET.to_vec();
        payload.extend_from_slice(point.as_bytes());
        let check = Sha256::digest(Sha256::digest(&payload));
        payload.extend_from_slice(&check[..4]);
        bs58::encode(payload).into_string()
    }

    fn sign(key: &SigningKey, text: &str) -> String {
        let sig: Signature = key.sign(text.as_bytes());
        let der = sig.normalize_s().unwrap_or(sig).to_der();
        der.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Each call gives a different message (the salt counts up), as real posts are.
    fn message(to: &str) -> String {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!(
            r#"{{"destination":{{"public_key":"{to}","domain":"epicbox.example","port":443}},"encrypted_message":"00","salt":"{n:016x}","nonce":"000000000000000000000000"}}"#
        )
    }

    fn post(state: &mut State, from: &SigningKey, to: &str, now: u64) -> Result<String, String> {
        let str = message(to);
        let slate = PostSlate {
            from: format!("{}@epicbox.example", address(from)),
            to: format!("{to}@epicbox.example"),
            signature: sign(from, &str),
            str,
        };
        state.post(slate, Principal::anonymous(), now)
    }

    fn pull_auth(key: &SigningKey, now: u64) -> SignedPull {
        let challenge = format!("{CHALLENGE_PREFIX}{}-abcd", now / 1_000_000_000);
        SignedPull { address: address(key), signature: sign(key, &challenge), challenge }
    }

    #[test]
    fn post_pull_made_round_trip() {
        let (alice, bob) = (signing(1), signing(2));
        let mut s = State::default();
        let id = post(&mut s, &alice, &address(&bob), T0).unwrap();
        let got = s.pull_signed(&pull_auth(&bob, T0), T0).unwrap().unwrap();
        assert_eq!(got.epicboxmsgid, id);
        // Alice can't read Bob's queue, and a stale challenge is refused.
        assert_eq!(s.pull_signed(&pull_auth(&alice, T0), T0).unwrap(), None);
        assert!(s.pull_signed(&pull_auth(&bob, T0), T0 + 21 * 60 * 1_000_000_000).is_err());
        let made = SignedMade { address: address(&bob), signature: sign(&bob, &id), epicboxmsgid: id };
        s.made_signed(&made, T0).unwrap();
        assert_eq!(s.pull_signed(&pull_auth(&bob, T0), T0).unwrap(), None);
        assert_eq!(s.counters.made, 1);
    }

    #[test]
    fn forged_or_wrong_signatures_are_refused() {
        let (alice, bob, eve) = (signing(1), signing(2), signing(3));
        let mut s = State::default();
        let str = message(&address(&bob));
        let forged = PostSlate {
            from: address(&alice),
            to: address(&bob),
            signature: sign(&eve, &str),
            str,
        };
        assert!(s.post(forged, Principal::anonymous(), T0).is_err());
        let id = post(&mut s, &alice, &address(&bob), T0).unwrap();
        let bad_made = SignedMade { address: address(&bob), signature: sign(&eve, &id), epicboxmsgid: id };
        assert!(s.made_signed(&bad_made, T0).is_err());
        assert_eq!(s.messages.len(), 1);
    }

    #[test]
    fn owner_claim_pulls_in_batches_and_messages_expire() {
        let (alice, maker) = (signing(1), signing(5));
        let owner = Principal::from_slice(&[7; 10]);
        let mut s = State::default();
        for i in 0..3 {
            post(&mut s, &alice, &address(&maker), T0 + i).unwrap();
        }
        assert!(s.pull_owned(&OwnerPull { address: address(&maker), limit: 10 }, owner, T0).is_err());
        let claim = format!("{CLAIM_PREFIX}{}", owner.to_text());
        s.claim(&address(&maker), &sign(&maker, &claim), owner).unwrap();
        let got = s.pull_owned(&OwnerPull { address: address(&maker), limit: 10 }, owner, T0).unwrap();
        assert_eq!(got.len(), 3);
        let ids: Vec<String> = got.iter().map(|d| d.epicboxmsgid.clone()).take(2).collect();
        assert_eq!(s.made_owned(&address(&maker), &ids, owner, T0).unwrap(), 2);
        s.purge(T0 + TTL_NS + 10);
        assert!(s.messages.is_empty());
        assert_eq!(s.counters.expired, 1);
    }

    fn post_to(state: &mut State, from: &SigningKey, to: &str, domain: &str, port: u16, now: u64) -> Result<String, String> {
        let str = format!(
            r#"{{"destination":{{"public_key":"{to}","domain":"{domain}","port":{port}}},"encrypted_message":"00","salt":"0000000000000000","nonce":"000000000000000000000000"}}"#
        );
        let slate = PostSlate {
            from: format!("{}@icpepicbox.btlabs.uk", address(from)),
            to: format!("{to}@{domain}"),
            signature: sign(from, &str),
            str,
        };
        state.post(slate, Principal::anonymous(), now)
    }

    #[test]
    fn foreign_destinations_are_forwarded_not_kept() {
        let (maker, buyer) = (signing(5), signing(6));
        let mut s = State::default();
        s.local_domains.insert("icpepicbox.btlabs.uk:443".into());
        let id = post_to(&mut s, &maker, &address(&buyer), "epicbox.epiccash.com", 443, T0).unwrap();
        // Not readable as a local queue.
        assert_eq!(s.pull_signed(&pull_auth(&buyer, T0), T0).unwrap(), None);
        let out = s.pull_outbound(10, T0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].relay, "epicbox.epiccash.com:443");
        assert!(out[0].to.ends_with("@epicbox.epiccash.com"));
        // A failure backs off, a success removes it.
        let fail = ForwardFailure { id: id.clone(), error: "refused".into() };
        assert_eq!(s.outbound_done(&[], &[fail], T0), (0, 0));
        assert!(s.pull_outbound(10, T0).is_empty());
        assert_eq!(s.pull_outbound(10, T0 + 31 * 1_000_000_000).len(), 1);
        assert_eq!(s.outbound_done(&[id], &[], T0), (1, 0));
        assert_eq!(s.counters.forwarded, 1);
        // A local destination stays here, and the domain compares case-insensitively.
        post_to(&mut s, &maker, &address(&buyer), "ICPepicbox.btlabs.uk", 443, T0).unwrap();
        assert!(s.pull_signed(&pull_auth(&buyer, T0), T0).unwrap().is_some());
    }

    #[test]
    fn a_relay_that_keeps_failing_is_given_up() {
        let (maker, buyer) = (signing(5), signing(6));
        let mut s = State::default();
        s.local_domains.insert("icpepicbox.btlabs.uk:443".into());
        let id = post_to(&mut s, &maker, &address(&buyer), "gone.example", 443, T0).unwrap();
        let fail = ForwardFailure { id, error: "connect".into() };
        let mut dropped = 0;
        for _ in 0..MAX_FORWARD_ATTEMPTS {
            dropped += s.outbound_done(&[], std::slice::from_ref(&fail), T0).1;
        }
        assert_eq!(dropped, 1);
        assert!(s.messages.is_empty());
        assert_eq!(s.counters.forward_failed, 1);
    }

    #[test]
    fn the_same_post_twice_is_one_message_even_after_it_was_taken() {
        let (alice, bob) = (signing(1), signing(2));
        let mut s = State::default();
        let str = message(&address(&bob));
        let slate = PostSlate { from: address(&alice), to: address(&bob), signature: sign(&alice, &str), str };
        let id = s.post(slate.clone(), Principal::anonymous(), T0).unwrap();
        assert_eq!(s.post(slate.clone(), Principal::anonymous(), T0 + 60).unwrap(), id);
        assert_eq!(s.messages.len(), 1);
        let made = SignedMade { address: address(&bob), signature: sign(&bob, &id), epicboxmsgid: id.clone() };
        s.made_signed(&made, T0).unwrap();
        // Replayed after Bob took it: still not a new message.
        assert_eq!(s.post(slate, Principal::anonymous(), T0 + 120).unwrap(), id);
        assert!(s.messages.is_empty());
        assert_eq!(s.counters_extra.as_ref().unwrap().duplicates, 2);
    }

    #[test]
    fn operators_may_only_add() {
        let (op, other) = (Principal::from_slice(&[1; 10]), Principal::from_slice(&[2; 10]));
        let mut s = State::default();
        assert!(!s.may_operate(&op, false));
        assert!(s.may_operate(&other, true), "a controller always may");
        s.operators = Some([op].into_iter().collect());
        assert!(s.may_operate(&op, false));
        assert!(!s.may_operate(&other, false));
        assert_eq!(s.add_local_domain("Relay.Example.org"), "relay.example.org:443");
        assert_eq!(s.add_local_domain("relay.example.org:8443"), "relay.example.org:8443");
        assert_eq!(s.local_domains.len(), 2);
    }

    #[test]
    fn caps_hold() {
        let (alice, bob) = (signing(1), signing(2));
        let mut s = State::default();
        for _ in 0..MAX_PENDING_PER_SENDER_AND_QUEUE {
            post(&mut s, &alice, &address(&bob), T0).unwrap();
        }
        assert!(post(&mut s, &alice, &address(&bob), T0).is_err());
    }

    /// A message epic-wallet's own code signed and encrypted (LEPIC conformance vector), so the
    /// k256 check here is proven against libsecp256k1's signatures, not only our own.
    #[test]
    fn accepts_a_stock_wallet_message() {
        let text = include_str!("../testdata/epicbox/message_v2_slate_floonet_custom_port.json");
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        let e = &v["expected"];
        let slate = PostSlate {
            from: e["from"].as_str().unwrap().into(),
            to: e["to"].as_str().unwrap().into(),
            str: e["str"].as_str().unwrap().into(),
            signature: e["signature"].as_str().unwrap().into(),
        };
        let mut s = State::default();
        let mut tampered = slate.clone();
        tampered.str = tampered.str.replacen("c2961bea", "c2961beb", 1);
        assert!(s.post(tampered, Principal::anonymous(), T0).is_err());
        s.post(slate.clone(), Principal::anonymous(), T0).unwrap();
        let queue = decode_key(&slate.to).unwrap().text;
        assert_eq!(s.queues.get(&queue).map(|q| q.len()), Some(1));
    }

    /// LEPIC's address vectors: every valid one decodes, every key-level invalid one is refused.
    #[test]
    fn address_vectors() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/epicbox");
        let mut checked = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if !name.starts_with("address_") {
                continue;
            }
            let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let Some(input) = v["inputs"]["text"].as_str().or(v["inputs"]["address"].as_str()) else { continue };
            let key_level = ["_checksum.", "_hex_key.", "_long_key.", "_short_key.", "_non_base58_character.", "_invalid_empty.", "_leading_space."];
            if name.starts_with("address_invalid_") {
                if key_level.iter().any(|k| name.contains(k)) {
                    assert!(decode_key(input).is_err(), "{name} should fail");
                    checked += 1;
                }
            } else {
                assert!(decode_key(input).is_ok(), "{name} should decode");
                checked += 1;
            }
        }
        assert!(checked >= 10, "only {checked} vectors checked");
    }
}
