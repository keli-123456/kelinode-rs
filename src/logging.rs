use std::sync::OnceLock;

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
            Self::Info => "INFO ",
            Self::Warn => "WARN ",
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
    format!(
        "{} {:<6} {}",
        level.as_str(),
        sanitize_component(component),
        message.trim()
    )
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
    use super::{format_log_line, LogLevel};

    #[test]
    fn formats_component_log_line() {
        assert_eq!(
            format_log_line(LogLevel::Info, "core", "started listeners=2"),
            "INFO  core   started listeners=2"
        );
    }

    #[test]
    fn sanitizes_component_names() {
        assert_eq!(
            format_log_line(LogLevel::Warn, "core/token", "hidden"),
            "WARN  coretoken hidden"
        );
    }
}
