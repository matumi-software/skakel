//! Pins `docs/parts.md`: a Skakel crate depends only on the Skakel crates that file allows.
//!
//! It sits here because this crate is the one every part may use and it has `serde_json` already.
//! It reads the workspace's dependencies from `cargo metadata`, so it covers every crate. Only
//! normal and build dependencies count against the table: a crate may use another in its own tests.
//! Three more rules hold for every kind of dependency or for the ones that ship: no cycle among the
//! Skakel crates even through dev-dependencies, no Skakel dependency that is optional (a feature
//! must not add an edge between parts), and the features a crate turns on in `skakel-proto` are the
//! ones for its side.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn crate_names(cell: &str) -> Vec<String> {
    cell.split(" and ")
        .map(|name| name.trim().trim_matches('`').to_owned())
        .collect()
}

/// The allowed dependencies between crates, from the table in `docs/parts.md`.
fn allowed_from_docs() -> BTreeMap<String, BTreeSet<String>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/parts.md");
    let text = std::fs::read_to_string(&path).expect("docs/parts.md is readable");
    let mut rows = vec![];
    for line in text
        .lines()
        .skip_while(|line| !line.starts_with("| Part |"))
    {
        if !line.starts_with('|') {
            break;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        // The header and the `|---|` line have no crate in backticks.
        if cells.len() == 3 && cells[1].starts_with('`') {
            rows.push((cells[0], cells[1], cells[2]));
        }
    }
    assert!(!rows.is_empty(), "the parts table is in docs/parts.md");

    let crates_of = |part: &str| -> Vec<String> {
        let (_, crates, _) = rows
            .iter()
            .find(|(name, _, _)| name.eq_ignore_ascii_case(part))
            .unwrap_or_else(|| panic!("docs/parts.md depends on '{part}', which is not a part"));
        crate_names(crates)
    };
    let mut allowed = BTreeMap::new();
    for (_, crates, depends_on) in &rows {
        let allowed_crates: BTreeSet<String> = if *depends_on == "nothing" {
            BTreeSet::new()
        } else {
            depends_on
                .split(',')
                .flat_map(|part| crates_of(part.trim()))
                .collect()
        };
        // The crates of one part may use each other: the virtual camera is two crates, one part.
        let own = crate_names(crates);
        for name in &own {
            let mut allowed_here = allowed_crates.clone();
            allowed_here.extend(own.iter().filter(|other| *other != name).cloned());
            allowed.insert(name.clone(), allowed_here);
        }
    }
    allowed
}

/// The features of `skakel-proto` each crate may turn on in a normal or build dependency. A crate
/// not listed turns on none.
const PROTO_FEATURES: &[(&str, &[&str])] = &[
    ("skakel-client", &["client"]),
    ("skakel-server", &["server"]),
];

fn workspace_packages() -> Vec<Value> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml");
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(&manifest)
        .output()
        .expect("cargo metadata runs");
    assert!(output.status.success(), "cargo metadata failed");
    let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
    metadata["packages"].as_array().unwrap().clone()
}

#[test]
fn no_skakel_crate_depends_on_itself_through_any_kind_of_dependency() {
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for package in workspace_packages() {
        let name = package["name"].as_str().unwrap().to_owned();
        let to = edges.entry(name.clone()).or_default();
        for dependency in package["dependencies"].as_array().unwrap() {
            let on = dependency["name"].as_str().unwrap();
            // A crate that names itself as a dev-dependency does it to turn on one of its own
            // features for its tests (a `test-util` feature); that is no cycle of crates.
            let itself_for_tests = on == name && dependency["kind"] == "dev";
            if on.starts_with("skakel-") && !itself_for_tests {
                to.insert(on.to_owned());
            }
        }
    }

    // Depth first, with the path so far, so a cycle is named.
    fn visit(
        name: &str,
        edges: &BTreeMap<String, BTreeSet<String>>,
        path: &mut Vec<String>,
        done: &mut BTreeSet<String>,
    ) -> Option<Vec<String>> {
        if let Some(at) = path.iter().position(|p| p == name) {
            let mut cycle = path[at..].to_vec();
            cycle.push(name.to_owned());
            return Some(cycle);
        }
        if done.contains(name) {
            return None;
        }
        path.push(name.to_owned());
        for next in edges.get(name).into_iter().flatten() {
            if let Some(cycle) = visit(next, edges, path, done) {
                return Some(cycle);
            }
        }
        path.pop();
        done.insert(name.to_owned());
        None
    }

    let mut done = BTreeSet::new();
    for name in edges.keys() {
        if let Some(cycle) = visit(name, &edges, &mut vec![], &mut done) {
            panic!("a dependency cycle: {}", cycle.join(" -> "));
        }
    }
}

#[test]
fn a_skakel_dependency_that_ships_is_never_optional_and_turns_on_only_its_sides_features() {
    let mut breaches = vec![];
    for package in workspace_packages() {
        let name = package["name"].as_str().unwrap();
        for dependency in package["dependencies"].as_array().unwrap() {
            let on = dependency["name"].as_str().unwrap();
            if !on.starts_with("skakel-") || dependency["kind"].as_str() == Some("dev") {
                continue;
            }
            if dependency["optional"].as_bool() == Some(true) {
                breaches.push(format!(
                    "{name} depends on {on} optionally, which makes a feature add an edge between parts"
                ));
            }
            let allowed: &[&str] = if on == "skakel-proto" {
                PROTO_FEATURES
                    .iter()
                    .find(|(krate, _)| *krate == name)
                    .map_or(&[], |(_, features)| features)
            } else {
                &[]
            };
            for feature in dependency["features"].as_array().unwrap() {
                let feature = feature.as_str().unwrap();
                if !allowed.contains(&feature) {
                    breaches.push(format!("{name} turns on {on}'s feature '{feature}'"));
                }
            }
        }
    }
    assert!(
        breaches.is_empty(),
        "{}",
        breaches.join(
            "
"
        )
    );
}

#[test]
fn a_crate_depends_only_on_the_skakel_crates_docs_parts_allows() {
    let allowed = allowed_from_docs();
    let mut breaches = vec![];
    let mut seen = BTreeSet::new();
    for package in workspace_packages() {
        let name = package["name"].as_str().unwrap();
        if !name.starts_with("skakel-") {
            continue;
        }
        seen.insert(name.to_owned());
        let Some(allowed_here) = allowed.get(name) else {
            breaches.push(format!("{name} is not in the parts table of docs/parts.md"));
            continue;
        };
        for dependency in package["dependencies"].as_array().unwrap() {
            let on = dependency["name"].as_str().unwrap();
            let kind = dependency["kind"].as_str();
            if on.starts_with("skakel-") && kind != Some("dev") && !allowed_here.contains(on) {
                breaches.push(format!(
                    "{name} depends on {on}, which docs/parts.md does not allow"
                ));
            }
        }
    }
    for name in allowed.keys() {
        if !seen.contains(name) {
            breaches.push(format!(
                "docs/parts.md lists {name}, which is not in the workspace"
            ));
        }
    }

    assert!(breaches.is_empty(), "{}", breaches.join("\n"));
}
