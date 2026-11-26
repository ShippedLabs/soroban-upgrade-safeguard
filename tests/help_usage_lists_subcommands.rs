// SPDX-License-Identifier: MIT
//! The `Usage:` block of the top-level `--help` is a hand-written
//! `override_usage` string, so it can drift from the generated `Commands:`
//! list. Every subcommand in that list must also have a usage line.

use std::process::Command;

fn help_stdout() -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--help")
        .output()
        .expect("failed to run binary with --help");
    String::from_utf8(output.stdout).expect("stdout was not valid UTF-8")
}

/// Lines of the section that starts at the line beginning with `header`,
/// up to the next blank line.
fn section<'a>(help: &'a str, header: &str) -> Vec<&'a str> {
    help.lines()
        .skip_while(|line| !line.starts_with(header))
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .collect()
}

#[test]
fn every_listed_subcommand_has_a_usage_line() {
    let help = help_stdout();

    let commands: Vec<&str> = section(&help, "Commands:")
        .iter()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| *name != "help")
        .collect();
    assert!(
        commands.len() >= 13,
        "failed to parse the Commands list: {commands:?}\n{help}"
    );

    // The first usage line starts after "Usage:", the rest are indented.
    let usage = {
        let mut lines = help
            .lines()
            .skip_while(|line| !line.starts_with("Usage:"))
            .take_while(|line| !line.trim().is_empty());
        let first = lines
            .next()
            .unwrap_or_default()
            .trim_start_matches("Usage:");
        std::iter::once(first)
            .chain(lines)
            .map(str::trim)
            .collect::<Vec<_>>()
    };

    for name in commands {
        let prefix = format!("soroban-upgrade-safeguard {name}");
        assert!(
            usage.iter().any(|line| line.starts_with(&prefix)),
            "subcommand `{name}` is listed under Commands: but has no Usage: line. Usage lines: {usage:#?}"
        );
    }
}
