//! The notes issuer's Cashu endpoints, as a wallet calls them: NUT-01 and
//! NUT-02 keys, NUT-23 BOLT11 quotes with a NUT-20 key, NUT-04 minting,
//! NUT-09 restore and NUT-07 state checks (bnap:notes 5.2, 8, 12).
//!
//! The issuer URL comes from a signed offer and must be on the origin the
//! offer came from (bnap:notes 5.1); every keyset's ID is recomputed from
//! the keys fetched, and a keyset whose ID differs is never used (5.2).

use bnap_core::offer::same_origin;
use cashu::nuts::{
    BlindedMessage, CheckStateRequest, CheckStateResponse, CurrencyUnit, Id, KeySetInfo,
    KeysResponse, KeysetResponse, MintQuoteBolt11Request, MintQuoteBolt11Response, MintRequest,
    MintResponse, PublicKey, RestoreRequest, RestoreResponse,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{Code, Refusal, Result};
use crate::records::KeysetRecord;
use crate::transport::{HttpRequest, Transport};

fn issuer_err(m: impl std::fmt::Display) -> Refusal {
    Refusal::new(
        Code::Issuer,
        format!("The notes issuer answered something the wallet cannot use: {m}."),
    )
}

/// One issuer.
pub struct Issuer<'a> {
    url: &'a str,
    transport: &'a dyn Transport,
}

impl<'a> Issuer<'a> {
    /// The issuer at `url`, which must be an `https` URL on `origin`.
    pub fn new(url: &'a str, origin: &str, transport: &'a dyn Transport) -> Result<Self> {
        if !url.starts_with("https://") || !same_origin(url, origin) {
            return Err(issuer_err(format!("its URL {url} is not on {origin}")));
        }
        Ok(Self { url, transport })
    }

    fn at(&self, path: &str) -> String {
        format!("{}{}", self.url.trim_end_matches('/'), path)
    }

    async fn call<T: DeserializeOwned>(&self, req: HttpRequest) -> Result<T> {
        let resp = self.transport.send(req).await.map_err(Refusal::network)?;
        if resp.status != 200 {
            return Err(issuer_err(format!("status {}", resp.status)));
        }
        serde_json::from_slice(&resp.body).map_err(issuer_err)
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.call(HttpRequest::new("GET", self.at(path))).await
    }

    async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        let body = serde_json::to_vec(body).map_err(issuer_err)?;
        self.call(
            HttpRequest::new("POST", self.at(path))
                .header("content-type", "application/json")
                .body(body),
        )
        .await
    }

    /// Every keyset the issuer lists (NUT-02).
    pub async fn keysets(&self) -> Result<Vec<KeySetInfo>> {
        Ok(self.get::<KeysetResponse>("/v1/keysets").await?.keysets)
    }

    /// One keyset's keys (NUT-01), its ID recomputed from them (5.2).
    pub async fn keyset(&self, id: &[u8; 33]) -> Result<KeysetRecord> {
        let want = Id::from_bytes(id).map_err(issuer_err)?;
        let r: KeysResponse = self.get(&format!("/v1/keys/{want}")).await?;
        let ks = r
            .keysets
            .into_iter()
            .find(|k| k.id == want)
            .ok_or_else(|| issuer_err("the keyset asked for is missing"))?;
        if ks.unit != CurrencyUnit::Sat {
            return Err(issuer_err("the keyset is not in sat"));
        }
        let final_expiry = ks
            .final_expiry
            .ok_or_else(|| issuer_err("the keyset has no final expiry"))?;
        ks.verify_id()
            .map_err(|_| issuer_err("the keyset's ID does not match its keys"))?;
        Ok(KeysetRecord {
            issuer: self.url.to_owned(),
            id: *id,
            keys: ks
                .keys
                .iter()
                .map(|(a, k)| (u64::from(*a), hex::encode(k.to_bytes())))
                .collect(),
            final_expiry,
            input_fee_ppk: ks.input_fee_ppk,
        })
    }

    /// A NUT-23 BOLT11 quote for `amount` sat, locked to `pubkey` (NUT-20).
    pub async fn quote(
        &self,
        amount: u64,
        pubkey: &[u8; 33],
    ) -> Result<MintQuoteBolt11Response<String>> {
        let pubkey = PublicKey::from_slice(pubkey).map_err(issuer_err)?;
        self.post(
            "/v1/mint/quote/bolt11",
            &MintQuoteBolt11Request {
                amount: amount.into(),
                unit: CurrencyUnit::Sat,
                description: None,
                pubkey: Some(pubkey),
            },
        )
        .await
    }

    /// NUT-04 minting of a paid quote.
    pub async fn mint(&self, req: &MintRequest<String>) -> Result<MintResponse> {
        self.post("/v1/mint/bolt11", req).await
    }

    /// NUT-09 restore.
    pub async fn restore(&self, outputs: Vec<BlindedMessage>) -> Result<RestoreResponse> {
        self.post("/v1/restore", &RestoreRequest { outputs }).await
    }

    /// NUT-07 state check.
    pub async fn check_state(&self, ys: Vec<PublicKey>) -> Result<CheckStateResponse> {
        self.post("/v1/checkstate", &CheckStateRequest { ys }).await
    }
}
