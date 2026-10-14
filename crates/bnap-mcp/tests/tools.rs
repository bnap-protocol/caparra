//! The three tools, called by an MCP client over an in-process transport,
//! against a wallet on the in-test BNAP server.

#![allow(clippy::missing_panics_doc, clippy::result_large_err, missing_docs)]

use std::sync::Arc;

use bnap_mcp::BnapTools;
use caparra_wallet::testkit::{self, Kit, ORIGIN, PRICE};
use rmcp::ServiceExt as _;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use serde_json::{Value, json};

#[derive(Debug, Clone, Default)]
struct Client;

impl rmcp::ClientHandler for Client {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

struct Session {
    client: RunningService<RoleClient, Client>,
    kit: Kit,
    _dir: tempfile::TempDir,
    wallet: Arc<caparra_wallet::Wallet>,
}

async fn session() -> Session {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let wallet = Arc::new(testkit::wallet(&kit, dir.path(), "mcp").await);
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    let tools = BnapTools::new(wallet.clone());
    tokio::spawn(async move {
        let running = tools.serve(server_io).await.unwrap();
        let _ = running.waiting().await;
    });
    let client = Client.serve(client_io).await.unwrap();
    Session {
        client,
        kit,
        _dir: dir,
        wallet,
    }
}

async fn call(
    s: &Session,
    tool: &'static str,
    args: Value,
) -> Result<CallToolResult, rmcp::ServiceError> {
    let Value::Object(map) = args else {
        panic!("object")
    };
    s.client
        .call_tool(CallToolRequestParams::new(tool).with_arguments(map))
        .await
}

fn structured(r: &CallToolResult) -> Value {
    r.structured_content.clone().expect("structured content")
}

fn error_code(r: &CallToolResult) -> String {
    assert_eq!(r.is_error, Some(true), "{r:?}");
    structured(r)["error"]["code"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn exactly_three_tools_and_none_takes_a_scheme() {
    let s = session().await;
    let tools = s.client.list_all_tools().await.unwrap();
    let mut names: Vec<_> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    assert_eq!(names, ["budget", "fetch_paid", "receipts"]);
    for t in &tools {
        let schema = serde_json::to_string(&t.input_schema).unwrap();
        assert!(
            !schema.contains("scheme"),
            "{} takes a scheme: {schema}",
            t.name
        );
        assert!(!schema.contains("key"), "{} takes a key: {schema}", t.name);
    }
    // An argument naming a scheme is refused, not ignored.
    let r = call(
        &s,
        "fetch_paid",
        json!({ "url": format!("{ORIGIN}/ln"), "scheme": "httpauth:L402" }),
    )
    .await;
    assert!(r.is_err() || r.unwrap().is_error == Some(true));
    assert_eq!(s.kit.pay.total(), 0);
}

#[tokio::test]
async fn fetch_paid_pays_within_the_caps_and_keeps_the_receipt() {
    let s = session().await;
    let r = call(&s, "fetch_paid", json!({ "url": format!("{ORIGIN}/ln") }))
        .await
        .unwrap();
    assert_ne!(r.is_error, Some(true), "{r:?}");
    let v = structured(&r);
    assert_eq!(v["status"], 200);
    assert!(
        v["body"]["text"]
            .as_str()
            .unwrap()
            .starts_with("paid content")
    );
    assert_eq!(v["payment"]["cost_sat"], PRICE + 1);
    let id = v["payment"]["receipt"].as_str().unwrap().to_owned();
    let r = call(&s, "receipts", json!({})).await.unwrap();
    assert_eq!(structured(&r)["receipts"][0]["id"], id.as_str());
    let r = call(&s, "receipts", json!({ "action": "verify", "id": id }))
        .await
        .unwrap();
    assert_eq!(structured(&r)["receipts"][0]["valid"], true);
}

#[tokio::test]
async fn a_model_cannot_raise_a_cap_or_pay_above_it() {
    let s = session().await;
    let hard = s.wallet.config().await.unwrap().policy.caps;
    // max_sat above the owner's per-request cap.
    let r = call(
        &s,
        "fetch_paid",
        json!({ "url": format!("{ORIGIN}/ln"), "max_sat": hard.per_request + 1 }),
    )
    .await
    .unwrap();
    assert_eq!(error_code(&r), "ABOVE_HARD_CAP");
    // budget set above the owner's cap.
    for cap in ["per-request", "per-task", "per-origin", "daily"] {
        let r = call(
            &s,
            "budget",
            json!({ "action": "set", "cap": cap, "sat": u64::MAX }),
        )
        .await
        .unwrap();
        assert_eq!(error_code(&r), "ABOVE_HARD_CAP", "{cap}");
    }
    // Narrowing works and holds.
    let r = call(
        &s,
        "budget",
        json!({ "action": "set", "cap": "per-request", "sat": 5 }),
    )
    .await
    .unwrap();
    assert_eq!(structured(&r)["caps_in_force"]["per_request"], 5);
    let r = call(&s, "fetch_paid", json!({ "url": format!("{ORIGIN}/ln") }))
        .await
        .unwrap();
    assert_eq!(error_code(&r), "BUDGET_EXCEEDED");
    assert_eq!(structured(&r)["error"]["remaining"], 5);
    assert_eq!(s.kit.pay.total(), 0);
}

#[tokio::test]
async fn tool_output_never_carries_keys_or_secrets() {
    let s = session().await;
    s.wallet
        .set_pay_source(caparra_wallet::PaySourceConfig::Nwc {
            uri: "nostr+walletconnect://abcd?secret=feedfacefeedface".into(),
        })
        .await
        .unwrap();
    let mut all = String::new();
    for (tool, args) in [
        ("fetch_paid", json!({ "url": format!("{ORIGIN}/ln") })),
        ("budget", json!({})),
        ("receipts", json!({})),
        ("receipts", json!({ "action": "verify" })),
    ] {
        let r = call(&s, tool, args).await.unwrap();
        all.push_str(&serde_json::to_string(&r).unwrap());
    }
    assert!(!all.contains("feedface"));
    assert!(!all.contains("mnemonic"));
    assert!(!all.contains("note_key"));
}

#[tokio::test]
async fn refusals_are_structured_with_the_cli_codes() {
    let s = session().await;
    let r = call(&s, "fetch_paid", json!({ "url": "http://api.example/ln" }))
        .await
        .unwrap();
    assert_eq!(error_code(&r), "BAD_INPUT");
    s.wallet
        .set_policy(|p| {
            p.allowed_schemes = vec!["bnap:notes".into()];
            Ok(())
        })
        .await
        .unwrap();
    let r = call(&s, "fetch_paid", json!({ "url": format!("{ORIGIN}/ln") }))
        .await
        .unwrap();
    assert_eq!(error_code(&r), "POLICY");
    let e = &structured(&r)["error"];
    assert!(e["scheme"].is_string());
    assert!(e["message"].as_str().unwrap().contains("not allowed"));
}
