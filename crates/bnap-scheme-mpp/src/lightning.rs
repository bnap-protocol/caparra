//! The `lightning` method's `charge` objects (draft-lightning-charge-00):
//! the request, the credential and the receipt.

use serde_json::{Map, Value, json};

use crate::challenge::Challenge;
use crate::json::{self, hex32, object, required, string};
use crate::{MppError, time};

/// The method identifier.
pub const METHOD: &str = "lightning";
/// The intent identifier.
pub const INTENT: &str = "charge";
/// The only currency the method defines.
pub const CURRENCY: &str = "sat";

/// The Lightning network an invoice is on (`methodDetails.network`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Bitcoin mainnet.
    Mainnet,
    /// Regtest.
    Regtest,
    /// Signet.
    Signet,
}

impl Network {
    /// The token the request carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Regtest => "regtest",
            Self::Signet => "signet",
        }
    }

    /// Reads a token; anything but the three names is `None`.
    #[must_use]
    pub fn from_token(s: &str) -> Option<Self> {
        match s {
            "mainnet" => Some(Self::Mainnet),
            "regtest" => Some(Self::Regtest),
            "signet" => Some(Self::Signet),
            _ => None,
        }
    }
}

/// The `request` of a `lightning` `charge` challenge (7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChargeRequest {
    /// The invoice amount in sat (a decimal string on the wire).
    pub amount: u64,
    /// The BOLT 11 invoice, authoritative.
    pub invoice: String,
    /// Its payment hash.
    pub payment_hash: [u8; 32],
    /// Its network.
    pub network: Network,
    /// A memo, if the server sent one.
    pub description: Option<String>,
}

impl ChargeRequest {
    /// `b64u(JCS(request))`, with `currency` `sat` and every convenience
    /// field of `methodDetails` filled in.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut v = json!({
            "amount": self.amount.to_string(),
            "currency": CURRENCY,
            "methodDetails": {
                "invoice": self.invoice,
                "network": self.network.as_str(),
                "paymentHash": hex::encode(self.payment_hash),
            },
        });
        if let Some(d) = &self.description {
            v["description"] = Value::String(d.clone());
        }
        json::encode(&v)
    }

    /// Reads a request in its canonical form. This implementation needs the
    /// `paymentHash` and `network` convenience fields (it does not decode
    /// invoices), and refuses members the draft does not define.
    pub fn decode(request: &str) -> Result<Self, MppError> {
        let v = json::decode(request.as_bytes())?;
        let m = object(
            &v,
            &[
                "amount",
                "currency",
                "description",
                "recipient",
                "externalId",
                "methodDetails",
            ],
            "request",
        )?;
        let amount = decimal(required(m, "amount", "request.amount")?)
            .ok_or(MppError::Malformed("request.amount"))?;
        if required(m, "currency", "request.currency")? != CURRENCY {
            return Err(MppError::Malformed("request.currency"));
        }
        string(m, "recipient", "request.recipient")?;
        string(m, "externalId", "request.externalId")?;
        let description = string(m, "description", "request.description")?.map(str::to_owned);
        let details = m
            .get("methodDetails")
            .ok_or(MppError::Malformed("request.methodDetails"))?;
        let d = object(
            details,
            &["invoice", "paymentHash", "network"],
            "request.methodDetails",
        )?;
        let invoice = required(d, "invoice", "methodDetails.invoice")?.to_owned();
        let payment_hash = hex32(
            required(d, "paymentHash", "methodDetails.paymentHash")?,
            "methodDetails.paymentHash",
        )?;
        let network = Network::from_token(required(d, "network", "methodDetails.network")?)
            .ok_or(MppError::Malformed("methodDetails.network"))?;
        Ok(Self {
            amount,
            invoice,
            payment_hash,
            network,
            description,
        })
    }
}

/// A positive decimal without sign or leading zeros.
fn decimal(s: &str) -> Option<u64> {
    let n: u64 = s.parse().ok()?;
    (n > 0 && n.to_string() == s).then_some(n)
}

/// A `Payment` credential of the `lightning` method (8): the challenge
/// echo and the preimage, as the token `b64u(JCS(credential))`.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    /// The echoed challenge.
    pub challenge: Challenge,
    /// A payer identifier, if the client sent one.
    pub source: Option<String>,
    /// The payment preimage.
    pub preimage: [u8; 32],
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The preimage is a bearer secret; it is never logged (12.4).
        f.debug_struct("Credential")
            .field("challenge", &self.challenge)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

const CHALLENGE_MEMBERS: [&str; 10] = [
    "id",
    "realm",
    "method",
    "intent",
    "request",
    "expires",
    "digest",
    "opaque",
    "header",
    "description",
];

impl Credential {
    /// A credential answering `challenge` with the preimage the payer got.
    #[must_use]
    pub fn new(challenge: Challenge, preimage: [u8; 32]) -> Self {
        Self {
            challenge,
            source: None,
            preimage,
        }
    }

    /// The token: `b64u(JCS(credential))`.
    #[must_use]
    pub fn encode(&self) -> String {
        let c = &self.challenge;
        let mut echo = Map::new();
        for (k, v) in [
            ("id", Some(&c.id)),
            ("realm", Some(&c.realm)),
            ("method", Some(&c.method)),
            ("intent", Some(&c.intent)),
            ("request", Some(&c.request)),
            ("expires", c.expires.as_ref()),
            ("digest", c.digest.as_ref()),
            ("opaque", c.opaque.as_ref()),
            ("header", c.header.as_ref()),
            ("description", c.description.as_ref()),
        ] {
            if let Some(v) = v {
                echo.insert(k.to_owned(), Value::String(v.clone()));
            }
        }
        let mut v = json!({
            "challenge": echo,
            "payload": { "preimage": hex::encode(self.preimage) },
        });
        if let Some(s) = &self.source {
            v["source"] = Value::String(s.clone());
        }
        json::encode(&v)
    }

    /// Reads a token in its one canonical form (module `json`): members
    /// `challenge` and `payload` (with only `preimage`, 64 lower-case hex
    /// digits), optionally `source`, nothing else.
    pub fn decode(token: &[u8]) -> Result<Self, MppError> {
        let value = json::decode(token)?;
        let members = object(&value, &["challenge", "payload", "source"], "credential")?;
        let source = string(members, "source", "credential.source")?.map(str::to_owned);
        let echo = object(
            members
                .get("challenge")
                .ok_or(MppError::Malformed("credential.challenge"))?,
            &CHALLENGE_MEMBERS,
            "credential.challenge",
        )?;
        let optional = |k| string(echo, k, "credential.challenge").map(|o| o.map(str::to_owned));
        let needed = |k| required(echo, k, "credential.challenge").map(str::to_owned);
        let challenge = Challenge {
            id: needed("id")?,
            realm: needed("realm")?,
            method: needed("method")?,
            intent: needed("intent")?,
            request: needed("request")?,
            expires: optional("expires")?,
            digest: optional("digest")?,
            opaque: optional("opaque")?,
            header: optional("header")?,
            description: optional("description")?,
        };
        let payload = object(
            members
                .get("payload")
                .ok_or(MppError::Malformed("credential.payload"))?,
            &["preimage"],
            "credential.payload",
        )?;
        let preimage = hex32(
            required(payload, "preimage", "payload.preimage")?,
            "payload.preimage",
        )?;
        Ok(Self {
            challenge,
            source,
            preimage,
        })
    }
}

/// The `Payment-Receipt` of a settled `lightning` charge (10.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// The challenge ID.
    pub challenge_id: String,
    /// The payment hash (`reference`, never the preimage).
    pub payment_hash: [u8; 32],
    /// Settlement time, Unix seconds.
    pub timestamp: u64,
}

impl Receipt {
    /// The field value: `b64u(JCS({challengeId, method, reference, status,
    /// timestamp}))`.
    #[must_use]
    pub fn encode(&self) -> String {
        json::encode(&json!({
            "challengeId": self.challenge_id,
            "method": METHOD,
            "reference": hex::encode(self.payment_hash),
            "status": "success",
            "timestamp": time::rfc3339(self.timestamp),
        }))
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;

    fn request() -> ChargeRequest {
        ChargeRequest {
            amount: 21,
            invoice: "lnfake21sat1ab".into(),
            payment_hash: [0xab; 32],
            network: Network::Regtest,
            description: None,
        }
    }

    fn raw(s: &str) -> String {
        String::from_utf8(URL_SAFE_NO_PAD.decode(s).unwrap()).unwrap()
    }

    #[test]
    fn a_request_is_jcs_with_string_amounts() {
        let r = request();
        let enc = r.encode();
        assert_eq!(
            raw(&enc),
            format!(
                r#"{{"amount":"21","currency":"sat","methodDetails":{{"invoice":"lnfake21sat1ab","network":"regtest","paymentHash":"{}"}}}}"#,
                "ab".repeat(32)
            )
        );
        assert_eq!(ChargeRequest::decode(&enc).unwrap(), r);
        let with = ChargeRequest {
            description: Some("Weather report".into()),
            ..request()
        };
        assert_eq!(ChargeRequest::decode(&with.encode()).unwrap(), with);
    }

    #[test]
    fn bad_requests_are_refused() {
        let hash = "ab".repeat(32);
        for body in [
            format!(r#"{{"amount":"021","currency":"sat","methodDetails":{{"invoice":"i","network":"regtest","paymentHash":"{hash}"}}}}"#),
            format!(r#"{{"amount":"0","currency":"sat","methodDetails":{{"invoice":"i","network":"regtest","paymentHash":"{hash}"}}}}"#),
            format!(r#"{{"amount":21,"currency":"sat","methodDetails":{{"invoice":"i","network":"regtest","paymentHash":"{hash}"}}}}"#),
            format!(r#"{{"amount":"21","currency":"BTC","methodDetails":{{"invoice":"i","network":"regtest","paymentHash":"{hash}"}}}}"#),
            format!(r#"{{"amount":"21","currency":"sat","methodDetails":{{"invoice":"i","network":"testnet","paymentHash":"{hash}"}}}}"#),
            r#"{"amount":"21","currency":"sat","methodDetails":{"invoice":"i","network":"regtest"}}"#.to_owned(),
            format!(r#"{{"amount":"21","currency":"sat","extra":"x","methodDetails":{{"invoice":"i","network":"regtest","paymentHash":"{hash}"}}}}"#),
        ] {
            let enc = URL_SAFE_NO_PAD.encode(&body);
            assert!(ChargeRequest::decode(&enc).is_err(), "{body}");
        }
    }

    #[test]
    fn a_credential_round_trips_and_hides_its_preimage() {
        let c = Credential::new(
            Challenge {
                id: "id".into(),
                realm: "r".into(),
                method: METHOD.into(),
                intent: INTENT.into(),
                request: request().encode(),
                expires: Some("2026-10-11T06:31:40Z".into()),
                opaque: Some("eyJhIjoiMSJ9".into()),
                ..Challenge::default()
            },
            [0xcd; 32],
        );
        let token = c.encode();
        assert_eq!(Credential::decode(token.as_bytes()).unwrap(), c);
        assert!(raw(&token).starts_with(r#"{"challenge":{"expires":"#));
        assert!(!format!("{c:?}").contains(&"cd".repeat(32)));
        let with_source = Credential {
            source: Some("did:key:z6Mk".into()),
            ..c.clone()
        };
        let d = Credential::decode(with_source.encode().as_bytes()).unwrap();
        assert_eq!(d.source.as_deref(), Some("did:key:z6Mk"));
    }

    #[test]
    fn bad_credentials_are_refused() {
        let p = "cd".repeat(32);
        for body in [
            format!(r#"{{"challenge":{{"id":"i","intent":"charge","method":"lightning","realm":"r","request":"q"}},"payload":{{"preimage":"{}"}}}}"#, p.to_uppercase()),
            format!(r#"{{"challenge":{{"id":"i","intent":"charge","method":"lightning","realm":"r","request":"q"}},"payload":{{"preimage":"{p}","x":"1"}}}}"#),
            format!(r#"{{"challenge":{{"id":"i","intent":"charge","method":"lightning","realm":"r"}},"payload":{{"preimage":"{p}"}}}}"#),
            format!(r#"{{"challenge":{{"id":"i","intent":"charge","method":"lightning","realm":"r","request":"q","x":"1"}},"payload":{{"preimage":"{p}"}}}}"#),
            format!(r#"{{"challenge":{{"id":"i","intent":"charge","method":"lightning","realm":"r","request":"q"}},"extra":"1","payload":{{"preimage":"{p}"}}}}"#),
            r#"{"challenge":{"id":"i","intent":"charge","method":"lightning","realm":"r","request":"q"}}"#.to_owned(),
            format!(r#"{{"challenge":{{"id":1,"intent":"charge","method":"lightning","realm":"r","request":"q"}},"payload":{{"preimage":"{p}"}}}}"#),
            format!(r#"{{"payload":{{"preimage":"{p}"}},"challenge":{{"id":"i","intent":"charge","method":"lightning","realm":"r","request":"q"}}}}"#),
        ] {
            let enc = URL_SAFE_NO_PAD.encode(&body);
            assert!(Credential::decode(enc.as_bytes()).is_err(), "{body}");
        }
        let ok = format!(
            r#"{{"challenge":{{"id":"i","intent":"charge","method":"lightning","realm":"r","request":"q"}},"payload":{{"preimage":"{p}"}}}}"#
        );
        assert!(Credential::decode(URL_SAFE_NO_PAD.encode(&ok).as_bytes()).is_ok());
    }

    #[test]
    fn a_receipt_names_the_payment_hash_never_the_preimage() {
        let r = Receipt {
            challenge_id: "kM9x".into(),
            payment_hash: [0xbc; 32],
            timestamp: 1_791_700_000,
        };
        assert_eq!(
            raw(&r.encode()),
            format!(
                r#"{{"challengeId":"kM9x","method":"lightning","reference":"{}","status":"success","timestamp":"2026-10-11T06:26:40Z"}}"#,
                "bc".repeat(32)
            )
        );
    }

    #[test]
    fn networks_have_three_names() {
        for n in [Network::Mainnet, Network::Regtest, Network::Signet] {
            assert_eq!(Network::from_token(n.as_str()), Some(n));
        }
        assert_eq!(Network::from_token("testnet"), None);
    }
}
