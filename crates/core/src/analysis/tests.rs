use super::*;

const NOW: i64 = 1_790_000_000_000; // 2026-09-21
const STRONG: &str = "x9$Lq!2vR#pW7zK@";

fn field(id: &str, field_type: &str, value: &str) -> FieldView {
    FieldView {
        id: id.into(),
        label: id.into(),
        field_type: field_type.into(),
        value: value.into(),
    }
}

fn login(id: &str, password: &str, url: &str, username: &str) -> AnalysisItem {
    AnalysisItem {
        id: id.into(),
        created_at: NOW - 10 * DAY_MS,
        data: ItemView {
            category: "login".into(),
            title: id.into(),
            fields: vec![
                field("username", "text", username),
                field("password", "concealed", password),
                field("url", "url", url),
                field("totp", "totp", ""),
            ],
            ..ItemView::default()
        },
    }
}

fn options() -> AnalysisOptions {
    AnalysisOptions {
        now: NOW,
        ..AnalysisOptions::default()
    }
}

fn kinds(report: &SecurityReport, id: &str) -> Vec<FindingKind> {
    let mut kinds: Vec<FindingKind> = report
        .findings
        .iter()
        .filter(|f| f.item_id == id && !f.dismissed)
        .map(|f| f.kind)
        .collect();
    kinds.sort();
    kinds
}

fn category(report: &SecurityReport, kind: FindingKind) -> &CategorySummary {
    report.categories.iter().find(|c| c.kind == kind).unwrap()
}

#[test]
fn empty_vault_scores_100() {
    let report = analyze(&[], &options());
    assert_eq!(report.score, 100);
    assert_eq!(report.rating, Rating::Excellent);
    assert_eq!(report.categories.len(), FindingKind::ALL.len());
    assert!(report.fix_first.is_empty());
}

#[test]
fn finds_weak_reused_similar_and_insecure() {
    let items = [
        login("weak", "123456", "https://shop.example", "me@example.com"),
        login("a", STRONG, "https://one.example", "me@example.com"),
        login("b", STRONG, "http://two.example/login", "me@example.com"),
        login("s1", "Sommer2023!Haus", "https://three.example", "me"),
        login("s2", "Sommer2024!Haus", "https://four.example", "me"),
        login("ok", "G7#kP2!mQ9$wX4&z", "https://five.example", "me"),
    ];
    let report = analyze(&items, &options());
    assert_eq!(kinds(&report, "weak"), [FindingKind::Weak]);
    assert_eq!(kinds(&report, "a"), [FindingKind::Reused]);
    assert_eq!(
        kinds(&report, "b"),
        [FindingKind::Reused, FindingKind::InsecureUrl]
    );
    assert_eq!(kinds(&report, "s1"), [FindingKind::Similar]);
    assert!(kinds(&report, "ok").is_empty());
    assert_eq!(
        report.reused_groups,
        [vec!["a".to_string(), "b".to_string()]]
    );
    assert_eq!(
        report.similar_groups,
        [vec!["s1".to_string(), "s2".to_string()]]
    );
    let reused = report
        .findings
        .iter()
        .find(|f| f.item_id == "a" && f.kind == FindingKind::Reused)
        .unwrap();
    assert_eq!(reused.related, ["b"]);
    assert_eq!(reused.fix, FixAction::ChangePassword);
    assert_eq!(category(&report, FindingKind::Reused).count, 2);
    assert!(report.score < 60, "{}", report.score);
    assert_eq!(report.logins, 6);
    // Breaches are unknown until a check ran.
    assert!(!report.breach_checked);
    assert!(!category(&report, FindingKind::Breached).checked);
    // The explanation adds up to the points lost (rounding aside).
    let lost: u32 = report.categories.iter().map(|c| c.points).sum();
    assert!((i64::from(100 - u32::from(report.score)) - i64::from(lost)).abs() <= 2);
}

#[test]
fn breaches_are_critical_and_come_first() {
    let items = [
        login("weak", "123456", "https://shop.example", "me"),
        login(
            "leaked",
            "Zebra-Kaffee-Fenster-17",
            "https://mail.example",
            "me",
        ),
    ];
    let mut opts = options();
    opts.breach_counts = Some(BTreeMap::from([("leaked".to_string(), 42)]));
    let report = analyze(&items, &opts);
    assert!(report.breach_checked);
    assert_eq!(report.findings[0].kind, FindingKind::Breached);
    assert_eq!(report.findings[0].breach_count, Some(42));
    assert_eq!(report.fix_first[0].item_id, "leaked");
    assert_eq!(report.fix_first[0].severity, Severity::Critical);
    assert_eq!(report.fix_first[1].item_id, "weak");
}

#[test]
fn two_factor_and_passkeys_from_the_directories() {
    let mut with_totp = login("totp", STRONG, "https://github.com", "me");
    with_totp.data.fields[3].value = "JBSWY3DPEHPK3PXP".into();
    let mut with_passkey = login(
        "passkey",
        "G7#kP2!mQ9$wX4&z",
        "https://github.com/login",
        "you",
    );
    with_passkey.data.passkeys = vec![serde_json::json!({ "rpId": "github.com" })];
    let items = [
        login(
            "plain",
            "Wq8#mZ2!pL5$vN9&",
            "https://github.com/login",
            "other",
        ),
        with_totp,
        with_passkey,
        login(
            "unknown",
            "Hk3!nB7#xR2$tY6@",
            "https://passbox-test.example",
            "me",
        ),
    ];
    let report = analyze(&items, &options());
    let plain = kinds(&report, "plain");
    assert!(plain.contains(&FindingKind::MissingTwoFactor), "{plain:?}");
    assert!(plain.contains(&FindingKind::PasskeyAvailable), "{plain:?}");
    let missing = report
        .findings
        .iter()
        .find(|f| f.item_id == "plain" && f.kind == FindingKind::MissingTwoFactor)
        .unwrap();
    assert_eq!(missing.domain.as_deref(), Some("github.com"));
    assert!(
        missing
            .documentation_url
            .as_deref()
            .unwrap()
            .starts_with("https://")
    );
    assert_eq!(missing.fix, FixAction::EnableTwoFactor);
    let totp = kinds(&report, "totp");
    assert!(!totp.contains(&FindingKind::MissingTwoFactor));
    assert!(totp.contains(&FindingKind::TotpInSameItem));
    assert!(totp.contains(&FindingKind::PasskeyAvailable));
    assert!(kinds(&report, "passkey").is_empty());
    assert!(kinds(&report, "unknown").is_empty());
    // Informational findings do not cost points.
    assert_eq!(category(&report, FindingKind::TotpInSameItem).points, 0);
}

#[test]
fn old_passwords_use_the_history() {
    let mut old = login("old", STRONG, "https://a.example", "me");
    old.created_at = NOW - 800 * DAY_MS;
    let mut changed = login("changed", "G7#kP2!mQ9$wX4&z", "https://b.example", "me");
    changed.created_at = NOW - 800 * DAY_MS;
    changed.data.password_history = vec![HistoryView {
        value: "Earlier-Kaffee-1".into(),
        replaced_at: NOW - 30 * DAY_MS,
    }];
    let mut unknown = login("unknown", "Hk3!nB7#xR2$tY6@", "https://c.example", "me");
    unknown.created_at = 0;
    let items = [old, changed, unknown];
    let report = analyze(&items, &options());
    assert_eq!(kinds(&report, "old"), [FindingKind::Old]);
    assert_eq!(report.findings[0].age_days, Some(800));
    assert!(kinds(&report, "changed").is_empty());
    assert!(kinds(&report, "unknown").is_empty());
    let mut off = options();
    off.old_after_days = 0;
    assert!(analyze(&items, &off).findings.is_empty());
    assert!(!category(&analyze(&items, &off), FindingKind::Old).checked);
}

#[test]
fn similar_to_an_earlier_password_of_the_same_item() {
    let mut item = login("rotated", "Fruehling2025!", "https://a.example", "me");
    item.data.password_history = vec![HistoryView {
        value: "Fruehling2024!".into(),
        replaced_at: NOW - DAY_MS,
    }];
    let report = analyze(&[item], &options());
    let similar = report
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::Similar)
        .unwrap();
    assert!(similar.similar_to_previous);
    assert!(similar.related.is_empty());
}

#[test]
fn cards_and_documents_expire() {
    let card = |id: &str, expiry: &str| AnalysisItem {
        id: id.into(),
        created_at: 0,
        data: ItemView {
            category: "card".into(),
            fields: vec![
                field("card_number", "concealed", "4111 1111 1111 1111"),
                FieldView {
                    id: "card_expiry".into(),
                    label: "Expiry date".into(),
                    field_type: "text".into(),
                    value: expiry.into(),
                },
            ],
            ..ItemView::default()
        },
    };
    let passport = AnalysisItem {
        id: "passport".into(),
        created_at: 0,
        data: ItemView {
            category: "identity".into(),
            fields: vec![FieldView {
                id: "f1".into(),
                label: "Gültig bis".into(),
                field_type: "text".into(),
                value: "01.10.2026".into(),
            }],
            ..ItemView::default()
        },
    };
    let items = [card("expired", "08/26"), card("valid", "12/30"), passport];
    let report = analyze(&items, &options());
    let expired = kinds(&report, "expired");
    assert!(expired.contains(&FindingKind::Expired));
    // Same card number twice.
    assert!(expired.contains(&FindingKind::Duplicate));
    assert_eq!(kinds(&report, "passport"), [FindingKind::Expiring]);
    let passport = report
        .findings
        .iter()
        .find(|f| f.item_id == "passport")
        .unwrap();
    assert_eq!(passport.expires.as_deref(), Some("2026-10-01"));
    assert_eq!(passport.days_left, Some(10));
    assert_eq!(passport.fix, FixAction::Renew);
    assert_eq!(report.duplicate_groups.len(), 1);
}

#[test]
fn lookalike_domains_among_saved_logins() {
    let items = [
        login("real1", STRONG, "https://www.sparkasse-hannover.de", "me"),
        login(
            "real2",
            "G7#kP2!mQ9$wX4&z",
            "https://banking.sparkasse-hannover.de",
            "me",
        ),
        login(
            "typo",
            "Hk3!nB7#xR2$tY6@",
            "https://sparkasse-hanover.de",
            "me",
        ),
        login(
            "homograph",
            "Wq8#mZ2!pL5$vN9&",
            &format!("https://{}", domain::idna_pair("pаypal.com").unwrap().0),
            "me",
        ),
    ];
    let report = analyze(&items, &options());
    let typo = report
        .findings
        .iter()
        .find(|f| f.item_id == "typo" && f.kind == FindingKind::Lookalike)
        .unwrap();
    assert_eq!(typo.lookalike_of.as_deref(), Some("sparkasse-hannover.de"));
    assert_eq!(typo.lookalike_reason, Some(LookalikeReason::Typo));
    assert_eq!(typo.related, ["real1", "real2"]);
    assert!(!kinds(&report, "real1").contains(&FindingKind::Lookalike));
    let homograph = report
        .findings
        .iter()
        .find(|f| f.item_id == "homograph" && f.kind == FindingKind::Lookalike)
        .unwrap();
    assert_eq!(homograph.lookalike_of.as_deref(), Some("paypal.com"));
    assert_eq!(homograph.lookalike_reason, Some(LookalikeReason::Homograph));
}

#[test]
fn duplicates_and_missing_fields() {
    let items = [
        login("one", STRONG, "https://mail.example", "Me@Example.com"),
        login(
            "two",
            "G7#kP2!mQ9$wX4&z",
            "https://www.mail.example/login",
            "me@example.com",
        ),
        login("nourl", "Hk3!nB7#xR2$tY6@", "", "me"),
        login("nouser", "Wq8#mZ2!pL5$vN9&", "https://x.example", ""),
    ];
    let report = analyze(&items, &options());
    assert!(kinds(&report, "one").contains(&FindingKind::Duplicate));
    assert_eq!(
        report.duplicate_groups,
        [vec!["one".to_string(), "two".to_string()]]
    );
    assert_eq!(kinds(&report, "nourl"), [FindingKind::MissingUrl]);
    assert_eq!(kinds(&report, "nouser"), [FindingKind::MissingUsername]);
}

#[test]
fn exposed_email_matches_the_breached_site() {
    let items = [
        login(
            "adobe",
            STRONG,
            "https://account.adobe.com",
            "me@example.com",
        ),
        login(
            "other",
            "G7#kP2!mQ9$wX4&z",
            "https://other.example",
            "me@example.com",
        ),
    ];
    let mut opts = options();
    opts.exposed_emails = vec![ExposedEmail {
        email: "ME@example.com".into(),
        breaches: vec![BreachInfo {
            name: "Adobe".into(),
            title: "Adobe".into(),
            domain: "adobe.com".into(),
            breach_date: "2013-10-04".into(),
            data_classes: vec!["Passwords".into()],
        }],
    }];
    let report = analyze(&items, &opts);
    let exposed = report
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::ExposedEmail)
        .unwrap();
    assert_eq!(exposed.item_id, "adobe");
    assert_eq!(exposed.breaches, ["Adobe"]);
    assert_eq!(exposed.email.as_deref(), Some("ME@example.com"));
    assert!(!kinds(&report, "other").contains(&FindingKind::ExposedEmail));
}

#[test]
fn dismissed_and_disabled_findings_do_not_count() {
    let mut weak = login("weak", "123456", "https://shop.example", "me");
    weak.data.security_ignore = vec!["weak".into()];
    let items = [weak.clone()];
    let report = analyze(&items, &options());
    assert_eq!(report.score, 100);
    assert!(report.findings.iter().all(|f| f.dismissed));
    assert_eq!(category(&report, FindingKind::Weak).dismissed, 1);
    assert_eq!(category(&report, FindingKind::Weak).count, 0);
    assert!(report.fix_first.is_empty());

    weak.data.security_ignore.clear();
    let mut opts = options();
    opts.disabled = vec![FindingKind::Weak];
    let report = analyze(&[weak], &opts);
    assert!(report.findings.is_empty());
    assert!(!category(&report, FindingKind::Weak).checked);
}

#[test]
fn trashed_items_are_skipped() {
    let mut item = login("t", "123456", "http://x.example", "");
    item.data.trashed_at = Some(1);
    let report = analyze(&[item], &options());
    assert!(report.findings.is_empty());
    assert_eq!(report.items, 0);
}

#[test]
fn dismissals_live_in_the_item() {
    let mut item = serde_json::Map::new();
    assert!(set_dismissed(&mut item, FindingKind::Weak, true));
    assert!(!set_dismissed(&mut item, FindingKind::Weak, true));
    assert!(set_dismissed(&mut item, FindingKind::Old, true));
    assert_eq!(item[IGNORE_KEY], serde_json::json!(["weak", "old"]));
    assert!(set_dismissed(&mut item, FindingKind::Weak, false));
    assert!(set_dismissed(&mut item, FindingKind::Old, false));
    assert!(!item.contains_key(IGNORE_KEY));
}

#[test]
fn reads_the_item_json_format() {
    let json = serde_json::json!({
        "id": "x",
        "createdAt": 5,
        "data": {
            "v": 1, "category": "login", "title": "Mail", "notes": "", "tags": [], "favorite": false,
            "fields": [{ "id": "password", "label": "Password", "type": "concealed", "value": "123456" }],
            "securityIgnore": ["missing_url"],
            "somethingNew": true
        }
    });
    let item: AnalysisItem = serde_json::from_value(json).unwrap();
    assert_eq!(item.created_at, 5);
    let report = analyze(&[item], &options());
    let codes: Vec<&str> = report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(codes.contains(&"weak"));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["findings"][0]["kind"], "weak");
    assert_eq!(json["findings"][0]["severity"], "high");
    assert_eq!(json["findings"][0]["fix"], "change_password");
    assert_eq!(json["categories"][0]["kind"], "breached");
    for kind in FindingKind::ALL {
        assert_eq!(FindingKind::parse(kind.as_str()), Some(kind));
    }
}

fn catalog(breaches: Vec<breaches::SiteBreach>) -> breaches::BreachCatalog {
    breaches::BreachCatalog {
        version: "test".into(),
        updated_at: breaches::BreachCatalog::newest_change(&breaches),
        breaches,
        ..breaches::BreachCatalog::default()
    }
}

fn site_breach(name: &str, domain: &str, added_ms: i64, classes: &[&str]) -> breaches::SiteBreach {
    let date = breaches::date_string(added_ms);
    breaches::SiteBreach {
        name: name.into(),
        title: name.into(),
        domain: domain.into(),
        breach_date: date.clone(),
        added_date: format!("{date}T00:00:00Z"),
        pwn_count: 1000,
        data_classes: classes.iter().map(|c| (*c).to_owned()).collect(),
        verified: true,
        ..breaches::SiteBreach::default()
    }
}

fn breached_site<'a>(report: &'a SecurityReport, id: &str) -> Option<&'a Finding> {
    report
        .findings
        .iter()
        .find(|f| f.item_id == id && f.kind == FindingKind::BreachedSite)
}

#[test]
fn breached_site_matches_older_passwords() {
    let breach_at = NOW - 5 * DAY_MS;
    let mut old = login("old", STRONG, "https://www.netflix.com/login", "me");
    old.created_at = NOW - 400 * DAY_MS;
    let mut changed = login("changed", "G7#kP2!mQ9$wX4&z", "https://netflix.com", "me2");
    changed.created_at = NOW - 400 * DAY_MS;
    changed.data.password_history = vec![HistoryView {
        value: "previous".into(),
        replaced_at: NOW - DAY_MS,
    }];
    let mut newer = login("newer", "Zq8!rT4#vB6$nM2&", "https://netflix.com", "me3");
    newer.created_at = NOW - DAY_MS;
    let mut unknown = login("unknown", "Hw3!kL9#pS5$dF7&", "https://netflix.com", "me4");
    unknown.created_at = 0;
    let other = login("other", "Yt6!gH2#jK8$lP4&", "https://netflix.de", "me5");
    let mut opts = options();
    opts.site_breaches = Some(catalog(vec![site_breach(
        "Netflix",
        "netflix.com",
        breach_at,
        &["Email addresses", "Passwords"],
    )]));
    let report = analyze(&[old, changed, newer, unknown, other], &opts);

    let f = breached_site(&report, "old").unwrap();
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.fix, FixAction::ChangePassword);
    assert_eq!(f.breaches, ["Netflix"]);
    assert_eq!(f.breach_names, ["Netflix"]);
    assert_eq!(f.data_classes, ["Email addresses", "Passwords"]);
    assert_eq!(
        f.breach_date.as_deref(),
        Some(breaches::date_string(breach_at).as_str())
    );
    assert!(!f.possibly);
    assert_eq!(f.domain.as_deref(), Some("netflix.com"));
    assert_eq!(
        f.documentation_url.as_deref(),
        Some("https://www.netflix.com/.well-known/change-password")
    );
    assert!(breached_site(&report, "changed").is_none());
    assert!(breached_site(&report, "newer").is_none());
    assert!(breached_site(&report, "other").is_none());
    let possibly = breached_site(&report, "unknown").unwrap();
    assert!(possibly.possibly);
    assert_eq!(possibly.severity, Severity::Medium);

    assert_eq!(report.breached_sites.len(), 1);
    let site = &report.breached_sites[0];
    assert_eq!(site.affected, ["old"]);
    assert_eq!(site.possibly, ["unknown"]);
    assert_eq!(site.fixed, ["changed"]);
    assert!(site.exposes_credentials);
    assert!(!report.breach_catalog.bundled);
    assert_eq!(report.breach_catalog.version, "test");
    assert_eq!(category(&report, FindingKind::BreachedSite).count, 2);
    assert!(
        report
            .fix_first
            .iter()
            .any(|p| p.item_id == "old" && p.kinds.contains(&FindingKind::BreachedSite))
    );
    assert!(report.score < 100);
}

#[test]
fn breached_site_severity_follows_the_data_classes() {
    let mut item = login("i", STRONG, "https://forum.example.org", "me");
    item.created_at = NOW - 400 * DAY_MS;
    let mut opts = options();
    opts.site_breaches = Some(catalog(vec![
        site_breach(
            "Forum",
            "forum.example.org",
            NOW - 30 * DAY_MS,
            &["Email addresses"],
        ),
        site_breach(
            "Shop",
            "shop.example.org",
            NOW - 30 * DAY_MS,
            &["Passwords"],
        ),
    ]));
    let report = analyze(std::slice::from_ref(&item), &opts);
    let f = breached_site(&report, "i").unwrap();
    assert_eq!(f.severity, Severity::Low);
    assert_eq!(f.breaches, ["Forum"]);

    // Dismissed like every other finding.
    item.data.security_ignore = vec!["breached_site".into()];
    let report = analyze(std::slice::from_ref(&item), &opts);
    assert!(breached_site(&report, "i").unwrap().dismissed);
    assert_eq!(category(&report, FindingKind::BreachedSite).dismissed, 1);

    // Turned off: neither findings nor the breach list.
    let mut off = opts.clone();
    off.disabled = vec![FindingKind::BreachedSite];
    let report = analyze(&[item], &off);
    assert!(report.breached_sites.is_empty());
    assert!(!category(&report, FindingKind::BreachedSite).checked);
}

#[test]
fn breached_site_uses_the_bundled_catalogue_by_default() {
    let mut item = login("adobe", STRONG, "https://adobe.com", "me");
    item.created_at = 1_000_000_000_000; // 2001
    let report = analyze(&[item], &options());
    assert!(report.breach_catalog.bundled);
    assert!(report.breach_catalog.entries > 500);
    let f = breached_site(&report, "adobe").unwrap();
    assert!(f.breach_names.contains(&"Adobe".to_owned()));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["breachCatalog"]["source"], "Have I Been Pwned");
    assert!(json["breachedSites"][0]["affected"].is_array());
    let finding = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["kind"] == "breached_site")
        .unwrap();
    assert!(finding["breachNames"].is_array());
    assert!(finding["dataClasses"].is_array());
}
