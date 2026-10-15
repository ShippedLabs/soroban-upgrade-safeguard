// SPDX-License-Identifier: MIT

//! Structured diagnostic logging with levels, correlation IDs, pair IDs,
//! event names, and comprehensive redaction rules.

use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Log level for structured diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl std::str::FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            other => Err(format!("unknown log level: {other}")),
        }
    }
}

/// Global settings for structured logging.
static LOG_LEVEL: Mutex<LogLevel> = Mutex::new(LogLevel::Info);
static JSON_LOGGING_ENABLED: AtomicBool = AtomicBool::new(false);
static HUMAN_LOGGING_ENABLED: AtomicBool = AtomicBool::new(true);
static DISABLE_TIMESTAMPS: AtomicBool = AtomicBool::new(false);
static CONFIGURED_PRIVATE_FIELDS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Configure global logging settings.
pub fn set_log_level(level: LogLevel) {
    if let Ok(mut l) = LOG_LEVEL.lock() {
        *l = level;
    }
}

pub fn get_log_level() -> LogLevel {
    LOG_LEVEL.lock().map(|l| *l).unwrap_or(LogLevel::Info)
}

pub fn set_json_logging(enabled: bool) {
    JSON_LOGGING_ENABLED.store(enabled, Ordering::SeqCst);
}

pub fn is_json_logging_enabled() -> bool {
    JSON_LOGGING_ENABLED.load(Ordering::SeqCst)
}

pub fn set_human_logging(enabled: bool) {
    HUMAN_LOGGING_ENABLED.store(enabled, Ordering::SeqCst);
}

pub fn is_human_logging_enabled() -> bool {
    HUMAN_LOGGING_ENABLED.load(Ordering::SeqCst)
}

pub fn set_disable_timestamps(disabled: bool) {
    DISABLE_TIMESTAMPS.store(disabled, Ordering::SeqCst);
}

pub fn is_timestamps_disabled() -> bool {
    DISABLE_TIMESTAMPS.load(Ordering::SeqCst)
}

pub fn set_configured_private_fields(fields: Vec<String>) {
    if let Ok(mut f) = CONFIGURED_PRIVATE_FIELDS.lock() {
        *f = fields;
    }
}

pub fn get_configured_private_fields() -> Vec<String> {
    CONFIGURED_PRIVATE_FIELDS.lock().map(|f| f.clone()).unwrap_or_default()
}

/// Redaction rules for structured logging.
/// Redacts secrets, sensitive URLs, arbitrary WASM names, and configured private fields.
pub fn redact_value(key: &str, value: &str) -> String {
    let lower_key = key.to_lowercase();
    let private_fields = get_configured_private_fields();
    for pf in private_fields {
        if lower_key == pf.to_lowercase() || lower_key.contains(&pf.to_lowercase()) {
            return "[REDACTED]".to_string();
        }
    }

    if lower_key.contains("secret")
        || lower_key.contains("password")
        || lower_key.contains("token")
        || lower_key.contains("api_key")
        || lower_key.contains("credential")
    {
        return "[REDACTED]".to_string();
    }

    if lower_key.contains("url") || lower_key.contains("endpoint") || value.starts_with("http://") || value.starts_with("https://") {
        return crate::rpc::redact_url(value);
    }

    if lower_key.contains("wasm") || lower_key.contains("path") || lower_key.contains("file") || value.ends_with(".wasm") {
        return crate::redact::redact_local_path(value);
    }

    value.to_string()
}

/// Structured log event record.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LogRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    pub level: LogLevel,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pair_id: Option<String>,
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    pub fields: serde_json::Map<String, serde_json::Value>,
    pub message: String,
}

/// Emit a structured log event.
pub fn log_event(
    level: LogLevel,
    event: &str,
    correlation_id: Option<&str>,
    pair_id: Option<&str>,
    fields: Option<serde_json::Map<String, serde_json::Value>>,
    message: &str,
) {
    if level < get_log_level() {
        return;
    }

    let fields = fields.unwrap_or_default();
    let mut redacted_fields = serde_json::Map::new();
    for (k, v) in fields {
        let v_str = match &v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let redacted_str = redact_value(&k, &v_str);
        if v.is_string() {
            redacted_fields.insert(k, serde_json::Value::String(redacted_str));
        } else if let Ok(parsed) = serde_json::from_str(&redacted_str) {
            redacted_fields.insert(k, parsed);
        } else {
            redacted_fields.insert(k, serde_json::Value::String(redacted_str));
        }
    }

    let timestamp = if is_timestamps_disabled() {
        None
    } else {
        Some(chrono_timestamp())
    };

    let record = LogRecord {
        timestamp,
        level,
        event: event.to_string(),
        correlation_id: correlation_id.map(|s| s.to_string()),
        pair_id: pair_id.map(|s| s.to_string()),
        fields: redacted_fields,
        message: message.to_string(),
    };

    if is_json_logging_enabled() {
        if let Ok(json) = serde_json::to_string(&record) {
            let mut stderr = std::io::stderr();
            let _ = writeln!(stderr, "{json}");
            let _ = stderr.flush();
        }
    }

    if is_human_logging_enabled() && !is_json_logging_enabled() {
        let mut stderr = std::io::stderr();
        let prefix = match level {
            LogLevel::Trace => "[TRACE]",
            LogLevel::Debug => "[DEBUG]",
            LogLevel::Info => "[INFO]",
            LogLevel::Warn => "[WARN]",
            LogLevel::Error => "[ERROR]",
        };
        let corr_str = correlation_id.map(|c| format!(" [corr={c}]")).unwrap_or_default();
        let pair_str = pair_id.map(|p| format!(" [pair={p}]")).unwrap_or_default();
        let _ = writeln!(stderr, "{prefix}{corr_str}{pair_str} {message}");
        let _ = stderr.flush();
    }
}

fn chrono_timestamp() -> String {
    // Simple ISO 8601 UTC timestamp without pulling in heavy chrono dependency if not needed, or std time.
    let now = std::time::SystemTime::now();
    if let Ok(duration) = now.duration_since(std::time::UNIX_EPOCH) {
        let secs = duration.as_secs();
        let days = secs / 86400;
        let remainder = secs % 86400;
        let hours = remainder / 3600;
        let mins = (remainder % 3600) / 60;
        let secs = remainder % 60;
        // Approximate calendar year/month/day from days since epoch
        let (y, m, d) = days_to_ymd(days);
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hours, mins, secs)
    } else {
        "1970-01-01T00:00:00Z".to_string()
    }
}

fn days_to_ymd(mut days: u64) -> (u32, u32, u32) {
    // Gregorian calendar epoch 1970-01-01
    let mut year = 1970;
    loop  {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let year_days = if leap { 366 } else { 365 };
        if days >= year_days {
            days -= year_days;
            year += 1;
        } else {
            break;
        }
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut month = 1;
    for &md in &month_days {
        if days >= md {
            days -= md;
            month += 1;
        } else {
            break;
        }
    }
    (year, month, (days + 1) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_parsing() {
        assert_eq!("trace".parse::<LogLevel>().unwrap(), LogLevel::Trace);
        assert_eq!("warn".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert_eq!("warning".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert!("invalid".parse::<LogLevel>().is_err());
        assert_eq!(
            "verbose".parse::<LogLevel>(),
            Err("unknown log level: verbose".to_string())
        );
    }

    #[test]
    fn test_redact_value() {
        assert_eq!(redact_value("secret_token", "my_secret_123"), "[REDACTED]");
        assert_eq!(redact_value("rpc_url", "https://user:pass@stellar.org?key=secret"), "https://[REDACTED]stellar.org");
        assert_eq!(redact_value("wasm_path", "/home/user/contracts/v1.wasm"), "<redacted>/v1.wasm");
    }

    #[test]
    fn test_log_record_json_serialization() {
        set_disable_timestamps(true);
        let mut fields = serde_json::Map::new();
        fields.insert("key".to_string(), serde_json::json!("value"));
        let record = LogRecord {
            timestamp: None,
            level: LogLevel::Info,
            event: "test_event".to_string(),
            correlation_id: Some("corr-123".to_string()),
            pair_id: Some("pair-456".to_string()),
            fields,
            message: "test message".to_string(),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"level\":\"info\""));
        assert!(json.contains("\"event\":\"test_event\""));
        assert!(json.contains("\"correlation_id\":\"corr-123\""));
        assert!(json.contains("\"pair_id\":\"pair-456\""));
        assert!(json.contains("\"message\":\"test message\""));
    }
}
