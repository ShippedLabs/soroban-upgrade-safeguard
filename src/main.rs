use anyhow::Result;
use clap::{Parser, ValueEnum};
use colored::Colorize;
use std::path::PathBuf;

mod diff;
mod loader;
mod mapper;
mod parser;
mod report;
mod spec;

/// Output format for the safety report.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
enum OutputFormat {
    /// Colored, human-readable report (default).
    #[default]
    Text,
    /// A single machine-readable JSON document for CI and dashboards.
    Json,
}

/// Minimum severity to print in text reports.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
enum MinSeverity {
    /// Print informational, warning, and critical findings.
    #[default]
    Info,
    /// Print warning and critical findings.
    Warning,
    /// Print only critical findings.
    Critical,
}

impl From<MinSeverity> for diff::Severity {
    fn from(value: MinSeverity) -> Self {
        match value {
            MinSeverity::Info => diff::Severity::Info,
            MinSeverity::Warning => diff::Severity::Warning,
            MinSeverity::Critical => diff::Severity::Critical,
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the previous (on-chain) WASM contract
    #[arg(value_name = "OLD_WASM")]
    old_wasm: PathBuf,

    /// Path to the new (to be deployed) WASM contract
    #[arg(value_name = "NEW_WASM")]
    new_wasm: PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Minimum severity to print in text output
    #[arg(long, value_enum, default_value_t = MinSeverity::Info)]
    min_severity: MinSeverity,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let json = args.format == OutputFormat::Json;

    // In JSON mode, decorative progress goes to stderr so stdout stays a
    // single, pristine JSON document. In text mode it stays on stdout
    // exactly as before.
    let progress = |line: String| {
        if json {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };

    progress("🔍 Soroban Upgrade Safeguard".to_string());
    progress("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string());

    progress(format!(
        "\n{}",
        "📦 Loading and Parsing contracts...".cyan().bold()
    ));

    // Old WASM
    let old = loader::load_wasm(&args.old_wasm)?;
    let old_meta = parser::extract_metadata(&old.bytes)?;
    let old_spec = spec::ContractSpec::from_entries(&old_meta.spec);
    progress(format!(
        "  {} {} ({} bytes)",
        "✅ Old:".green().bold(),
        old.path,
        old.bytes.len()
    ));
    progress(format!("     └─ {}", old_spec.summary().dimmed()));

    // New WASM
    let new = loader::load_wasm(&args.new_wasm)?;
    let new_meta = parser::extract_metadata(&new.bytes)?;
    let new_spec = spec::ContractSpec::from_entries(&new_meta.spec);
    progress(format!(
        "  {} {} ({} bytes)",
        "✅ New:".green().bold(),
        new.path,
        new.bytes.len()
    ));
    progress(format!("     └─ {}", new_spec.summary().dimmed()));

    // Run comparison
    progress(format!(
        "\n{}",
        "🔬 Analyzing structural compatibility...".cyan().bold()
    ));
    let diff_report = diff::compare(&old_spec, &new_spec);

    // Generate Safety Report
    let safety_report = report::SafetyReport::new(&diff_report);

    if json {
        // Single JSON document to stdout; no decorative text, no ANSI codes.
        println!(
            "{}",
            serde_json::to_string_pretty(&safety_report.to_json())?
        );
    } else {
        println!(
            "{}",
            safety_report.generate_summary_text(args.min_severity.into())
        );
    }

    if !safety_report.is_safe {
        std::process::exit(1);
    }

    Ok(())
}
