//! Build rule (concept §3.10, §6.6): AI code gets no keys. `passbox-ai`
//! must not depend on `passbox-core` or `passbox-client`, directly or
//! through any other crate. Checked against the manifest and the full
//! dependency closure in `Cargo.lock`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const FORBIDDEN: &[&str] = &[
    "passbox-core",
    "passbox-client",
    "passbox-core-wasm",
    "passbox-ffi",
];

#[test]
fn manifest_has_no_forbidden_dependency() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("Cargo.toml");
    for line in manifest.lines() {
        let name = line
            .split(['=', '.', ' '])
            .next()
            .unwrap_or_default()
            .trim();
        assert!(
            !FORBIDDEN.contains(&name),
            "crates/ai/Cargo.toml must not depend on {name}: AI code gets no keys (docs/architecture/ai-gateway.md)"
        );
    }
}

/// `name -> dependency names` from Cargo.lock (versions stripped).
fn lockfile_graph() -> BTreeMap<String, Vec<String>> {
    let lock =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock"))
            .expect("Cargo.lock");
    let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for block in lock.split("[[package]]").skip(1) {
        let mut name = None;
        let mut deps = Vec::new();
        let mut in_deps = false;
        for line in block.lines() {
            let line = line.trim();
            if let Some(n) = line.strip_prefix("name = ") {
                name = Some(n.trim_matches('"').to_owned());
            } else if line.starts_with("dependencies = [") {
                in_deps = true;
            } else if in_deps && line.starts_with(']') {
                in_deps = false;
            } else if in_deps {
                let dep = line.trim_matches([',', '"']);
                deps.push(dep.split(' ').next().unwrap_or_default().to_owned());
            }
        }
        if let Some(name) = name {
            graph.entry(name).or_default().extend(deps);
        }
    }
    graph
}

#[test]
fn dependency_closure_has_no_forbidden_crate() {
    let graph = lockfile_graph();
    assert!(
        graph.contains_key("passbox-ai"),
        "passbox-ai is in Cargo.lock"
    );
    let mut seen = BTreeSet::new();
    let mut stack = vec![("passbox-ai".to_owned(), vec!["passbox-ai".to_owned()])];
    while let Some((name, path)) = stack.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        assert!(
            !FORBIDDEN.contains(&name.as_str()) || name == "passbox-ai",
            "passbox-ai depends on {name} through {}: AI code gets no keys",
            path.join(" -> ")
        );
        for dep in graph.get(&name).into_iter().flatten() {
            let mut next = path.clone();
            next.push(dep.clone());
            stack.push((dep.clone(), next));
        }
    }
    // The check is meaningful: it walked real dependencies.
    assert!(seen.contains("serde_json") && seen.contains("ureq"));
}
