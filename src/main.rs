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
    /// Markdown report suitable for PR comments and CI summaries.
    Markdown,
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
}

fn main() -> Result<()> {
    let args = Args::parse();
    let structured_output = args.format != OutputFormat::Text;

    // In structured modes, decorative progress goes to stderr so stdout stays
    // a pristine document. In text mode it stays on stdout exactly as before.
    let progress = |line: String| {
        if structured_output {
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

    match args.format {
        OutputFormat::Text => println!("{}", safety_report.generate_summary_text()),
        OutputFormat::Json => {
            // Single JSON document to stdout; no decorative text, no ANSI codes.
            println!(
                "{}",
                serde_json::to_string_pretty(&safety_report.to_json())?
            );
        }
        OutputFormat::Markdown => println!("{}", safety_report.generate_markdown()),
    }

    if !safety_report.is_safe {
        std::process::exit(1);
    }

    Ok(())
}
