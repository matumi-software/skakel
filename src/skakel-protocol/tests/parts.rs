//! Pins `docs/parts.md`: a Skakel crate depends only on the Skakel crates that file allows.
//!
//! It sits here because this crate is the one every part may use and it has `serde_json` already.
//! It reads the workspace's dependencies from `cargo metadata`, so it covers every crate. Only
//! normal and build dependencies count: a crate may use another in its own tests.

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

#[test]
fn a_crate_depends_only_on_the_skakel_crates_docs_parts_allows() {
    let allowed = allowed_from_docs();
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

    let mut breaches = vec![];
    let mut seen = BTreeSet::new();
    for package in metadata["packages"].as_array().unwrap() {
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
