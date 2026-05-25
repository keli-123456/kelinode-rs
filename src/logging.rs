use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    fn from_env_value(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "debug" => Self::Debug,
            "warn" | "warning" => Self::Warn,
            "error" => Self::Error,
            _ => Self::Info,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

pub fn debug(component: &str, message: impl AsRef<str>) {
    emit(LogLevel::Debug, component, message);
}

pub fn info(component: &str, message: impl AsRef<str>) {
    emit(LogLevel::Info, component, message);
}

pub fn warn(component: &str, message: impl AsRef<str>) {
    emit(LogLevel::Warn, component, message);
}

pub fn error(component: &str, message: impl AsRef<str>) {
    emit(LogLevel::Error, component, message);
}

fn emit(level: LogLevel, component: &str, message: impl AsRef<str>) {
    if level < configured_level() {
        return;
    }
    eprintln!("{}", format_log_line(level, component, message.as_ref()));
}

fn configured_level() -> LogLevel {
    static LEVEL: OnceLock<LogLevel> = OnceLock::new();
    *LEVEL.get_or_init(|| {
        std::env::var("V2NODE_LOG_LEVEL")
            .or_else(|_| std::env::var("KELI_NODE_LOG_LEVEL"))
            .map(|value| LogLevel::from_env_value(&value))
            .unwrap_or(LogLevel::Info)
    })
}

fn format_log_line(level: LogLevel, component: &str, message: &str) -> String {
    format_log_line_at(level, component, message, unix_now())
}

fn format_log_line_at(level: LogLevel, component: &str, message: &str, unix_secs: u64) -> String {
    format!(
        "[{}] {} {} {}",
        level.as_str(),
        format_timestamp(unix_secs),
        sanitize_component(component),
        message.trim()
    )
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn format_timestamp(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let seconds = unix_secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    format!("{year:04}/{month:02}/{day:02} {hour:02}:{minute:02}:{second:02}")
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year as i32, month as u32, day as u32)
}

fn sanitize_component(component: &str) -> String {
    let value = component
        .trim()
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || *character == '-' || *character == '_'
        })
        .collect::<String>();
    if value.is_empty() {
        "agent".to_string()
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::{format_log_line_at, format_timestamp, LogLevel};

    #[test]
    fn formats_component_log_line() {
        assert_eq!(
            format_log_line_at(LogLevel::Info, "core", "started listeners=2", 0),
            "[INFO] 1970/01/01 00:00:00 core started listeners=2"
        );
    }

    #[test]
    fn sanitizes_component_names() {
        assert_eq!(
            format_log_line_at(LogLevel::Warn, "core/token", "hidden", 1_591_947_416),
            "[WARN] 2020/06/12 07:36:56 coretoken hidden"
        );
    }

    #[test]
    fn formats_service_timestamp() {
        assert_eq!(format_timestamp(1_591_947_416), "2020/06/12 07:36:56");
    }
}
