//! The gateway with a recording fake provider: what reaches a model, and
//! what happens when AI is off or the model misbehaves.

use std::sync::{Arc, Mutex};

use passbox_ai::import_mapping::{self, Source};
use passbox_ai::provider::{AiProvider, AiRequest, HttpPost, ModelLocation, OpenAiCompatible};
use passbox_ai::security_copilot::{self, FindingKind, Findings, PlanSource, SiteFindings};
use passbox_ai::{AiError, AiSettings, FeatureId, Gateway, ProviderSettings, SecretGuard};
use serde_json::{Value, json};

/// Records every request and answers with a fixed value.
#[derive(Clone)]
struct Recorder {
    location: ModelLocation,
    answer: Value,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Recorder {
    fn new(location: ModelLocation, answer: Value) -> Self {
        Self {
            location,
            answer,
            seen: Arc::default(),
        }
    }

    fn sent(&self) -> String {
        self.seen.lock().unwrap().join("\n")
    }
}

impl AiProvider for Recorder {
    fn id(&self) -> &str {
        "recorder"
    }
    fn location(&self) -> ModelLocation {
        self.location
    }
    fn complete(&self, request: &AiRequest) -> passbox_ai::Result<Value> {
        self.seen
            .lock()
            .unwrap()
            .push(format!("{}\n{}", request.system(), request.input()));
        Ok(self.answer.clone())
    }
}

fn settings(features: &[FeatureId], location: ModelLocation) -> AiSettings {
    AiSettings {
        enabled: true,
        provider: Some(ProviderSettings {
            location,
            endpoint: "http://localhost:11434/v1".into(),
            model: "llama3.2".into(),
            api_key_item: None,
            jurisdiction: None,
        }),
        features: features.to_vec(),
    }
}

fn gateway(recorder: &Recorder, features: &[FeatureId]) -> Gateway {
    Gateway::new(
        settings(features, recorder.location),
        Some(Box::new(recorder.clone())),
    )
}

/// A CSV whose cells are all distinctive, so any leak is visible.
fn table() -> (Vec<String>, Vec<Vec<String>>) {
    let headers = [
        "Bezeichnung",
        "Anmeldung",
        "Geheim",
        "Webadresse2",
        "Zweitfaktor",
        "Kundennr",
    ]
    .map(String::from)
    .to_vec();
    let rows = vec![
        [
            "Bank of Ada",
            "ada.lovelace@example.org",
            "Tr0ub4dor&3xyzQ!",
            "https://bank.example.org/login",
            "JBSWY3DPEHPK3PXP",
            "4711081",
        ],
        [
            "Mail",
            "charles.babbage@example.org",
            "Zq8#mW2$vK9!pL4x",
            "https://mail.example.org",
            "otpauth://totp/Mail?secret=GEZDGNBVGY3TQOJQ",
            "4711082",
        ],
    ]
    .into_iter()
    .map(|r| r.map(String::from).to_vec())
    .collect();
    (headers, rows)
}

#[test]
fn no_cell_value_reaches_the_provider() {
    let (headers, rows) = table();
    let current: Vec<String> = ["title", "field", "field", "field", "field", "field"]
        .map(String::from)
        .to_vec();
    let recorder = Recorder::new(
        ModelLocation::Cloud,
        json!({ "columns": [
            { "index": 1, "target": "username", "confidence": "high" },
            { "index": 2, "target": "password", "confidence": "high" },
            { "index": 3, "target": "url", "confidence": "high" },
            { "index": 4, "target": "totp", "confidence": "medium" },
            { "index": 5, "target": "field", "confidence": "low" },
            // Not unknown: ignored.
            { "index": 0, "target": "notes", "confidence": "high" }
        ]}),
    );
    let gw = gateway(&recorder, &[FeatureId::ImportMapping]);
    let input = import_mapping::redact_columns(&headers, &rows, &current, &[1, 2, 3, 4, 5]);
    let proposal = import_mapping::suggest(&gw, &input);
    assert_eq!(proposal.source, Source::Ai);
    assert_eq!(
        proposal.mapping,
        ["title", "username", "password", "url", "totp", "field"]
    );
    assert_eq!(proposal.changed, vec![1, 2, 3, 4]);

    let sent = recorder.sent();
    assert!(!sent.is_empty());
    for row in &rows {
        for cell in row {
            assert!(!sent.contains(cell.as_str()), "cell {cell:?} was sent");
            // Not even parts of longer values.
            for part in cell.split(['@', '/', '.', '?', '=', ':']) {
                if part.len() >= 8 {
                    assert!(!sent.contains(part), "part {part:?} of {cell:?} was sent");
                }
            }
        }
    }
    assert!(sent.contains("Webadresse2"));
    let log = gw.log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].feature, FeatureId::ImportMapping);
    assert_eq!(log[0].outcome, "ok");
}

#[test]
fn off_by_default_and_per_feature() {
    let (headers, rows) = table();
    let current = vec!["field".to_owned(); 6];
    let input = import_mapping::redact_columns(&headers, &rows, &current, &[0, 1, 2, 3, 4, 5]);

    // AI off: patterns only, and the provider is never called.
    let recorder = Recorder::new(ModelLocation::OnDevice, json!({}));
    let off = Gateway::new(AiSettings::default(), Some(Box::new(recorder.clone())));
    let proposal = import_mapping::suggest(&off, &input);
    assert_eq!(proposal.source, Source::Patterns);
    assert!(matches!(
        proposal.fallback_reason,
        Some(AiError::NotAllowed(_))
    ));
    assert_eq!(
        proposal.mapping,
        ["field", "username", "secret", "url", "totp", "field"]
    );
    assert_eq!(recorder.sent(), "");

    // Only the security copilot is on: import mapping stays local.
    let other = gateway(&recorder, &[FeatureId::SecurityCopilot]);
    assert_eq!(
        import_mapping::suggest(&other, &input).source,
        Source::Patterns
    );
    assert_eq!(recorder.sent(), "");
    assert!(other.log().is_empty());
}

#[test]
fn invalid_answers_fall_back() {
    let (headers, rows) = table();
    let current = vec!["field".to_owned(); 6];
    let input = import_mapping::redact_columns(&headers, &rows, &current, &[3]);
    for answer in [
        json!({ "columns": [{ "index": 99, "target": "url", "confidence": "high" }] }),
        json!({ "columns": [{ "index": 3, "target": "rm -rf", "confidence": "high" }] }),
        json!("not an object"),
    ] {
        let recorder = Recorder::new(ModelLocation::SelfHosted, answer);
        let gw = gateway(&recorder, &[FeatureId::ImportMapping]);
        let proposal = import_mapping::suggest(&gw, &input);
        assert_eq!(proposal.source, Source::Patterns);
        assert_eq!(proposal.mapping[3], "url");
        assert_eq!(gw.log()[0].outcome, "invalid");
    }
}

fn findings() -> Findings {
    Findings {
        analyzed: 3,
        breach_checked: false,
        sites: vec![
            SiteFindings {
                host: Some("gmx.de".into()),
                kinds: vec![FindingKind::Reused],
            },
            SiteFindings {
                host: Some("paypal.com".into()),
                kinds: vec![FindingKind::Reused, FindingKind::Weak],
            },
        ],
    }
}

#[test]
fn copilot_cloud_gets_placeholders_and_answers_are_restored() {
    let recorder = Recorder::new(
        ModelLocation::Cloud,
        json!({
            "summary": "Zwei Konten teilen ein Passwort.",
            "steps": [
                { "kind": "reused", "title": "Passwort für Site A ändern", "detail": "Site A und Site B nutzen dasselbe Passwort.", "sites": ["Site A", "evil.example"] },
                { "kind": "breached", "title": "Invented", "detail": "No such finding" }
            ]
        }),
    );
    let gw = gateway(&recorder, &[FeatureId::SecurityCopilot]);
    let mut guard = SecretGuard::new();
    guard.add("hunter2-password");
    let plan = security_copilot::plan(&gw, &findings(), "de", &guard);
    assert_eq!(plan.source, PlanSource::Ai);
    let sent = recorder.sent();
    assert!(
        !sent.contains("gmx.de") && !sent.contains("paypal.com"),
        "{sent}"
    );
    assert!(sent.contains("Site A"));
    let reused = &plan.steps[0];
    assert_eq!(reused.kind, FindingKind::Reused);
    assert_eq!(reused.count, 2);
    assert_eq!(
        reused.title.as_deref(),
        Some("Passwort für paypal.com ändern")
    );
    // Sites the model invented are dropped.
    assert_eq!(reused.sites, vec!["paypal.com"]);
    // The invented "breached" step is dropped; "weak" keeps the rule text.
    assert!(plan.steps.iter().all(|s| s.kind != FindingKind::Breached));
    let weak = plan
        .steps
        .iter()
        .find(|s| s.kind == FindingKind::Weak)
        .unwrap();
    assert_eq!(weak.title, None);
}

#[test]
fn copilot_without_ai_uses_rules() {
    let plan = security_copilot::plan(&Gateway::disabled(), &findings(), "en", &SecretGuard::new());
    assert_eq!(plan.source, PlanSource::Rules);
    assert_eq!(plan.steps[0].kind, FindingKind::Reused);
    assert!(plan.fallback_reason.is_some());
}

#[test]
fn policy_blocks_cloud() {
    let recorder = Recorder::new(ModelLocation::Cloud, json!({ "columns": [] }));
    let gw = gateway(&recorder, &[FeatureId::ImportMapping]).with_policy(
        passbox_ai::gateway::AiPolicy {
            allowed_locations: Some(vec![ModelLocation::OnDevice, ModelLocation::SelfHosted]),
            ..Default::default()
        },
    );
    let (headers, rows) = table();
    let input = import_mapping::redact_columns(&headers, &rows, &[], &[1]);
    let proposal = import_mapping::suggest(&gw, &input);
    assert_eq!(proposal.source, Source::Patterns);
    assert_eq!(recorder.sent(), "");
}

/// Captures the HTTP request of the OpenAI-compatible provider.
type Captured = (String, Vec<(String, String)>, Value);

struct FakeHttp {
    seen: Arc<Mutex<Vec<Captured>>>,
}

impl HttpPost for FakeHttp {
    fn post(
        &self,
        url: &str,
        headers: &[(&str, String)],
        body: Vec<u8>,
    ) -> passbox_ai::Result<(u16, Vec<u8>)> {
        self.seen.lock().unwrap().push((
            url.to_owned(),
            headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
            serde_json::from_slice(&body).unwrap(),
        ));
        let content = "```json\n{\"columns\":[{\"index\":3,\"target\":\"url\",\"confidence\":\"high\"}]}\n```";
        Ok((
            200,
            serde_json::to_vec(&json!({ "choices": [{ "message": { "content": content } }] }))
                .unwrap(),
        ))
    }
}

#[test]
fn openai_compatible_request_shape() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let provider = OpenAiCompatible::new(
        "cloud",
        "https://api.example.eu/v1/",
        "small-model",
        Some("sk-test-key".into()),
        ModelLocation::Cloud,
    )
    .unwrap()
    .with_http(Box::new(FakeHttp { seen: seen.clone() }));
    let gw = Gateway::new(
        settings(&[FeatureId::ImportMapping], ModelLocation::Cloud),
        Some(Box::new(provider)),
    );
    let (headers, rows) = table();
    let input = import_mapping::redact_columns(&headers, &rows, &[], &[3]);
    let proposal = import_mapping::suggest(&gw, &input);
    assert_eq!(proposal.source, Source::Ai);
    let seen = seen.lock().unwrap();
    let (url, headers, body) = &seen[0];
    assert_eq!(url, "https://api.example.eu/v1/chat/completions");
    assert_eq!(
        headers[0],
        ("authorization".into(), "Bearer sk-test-key".into())
    );
    assert_eq!(body["model"], "small-model");
    // The key is a header, never part of the prompt.
    assert!(!body.to_string().contains("sk-test-key"));
}
