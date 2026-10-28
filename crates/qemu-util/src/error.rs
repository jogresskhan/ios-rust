//! Port of `util/error.c` — QEMU's Error carries a human string + class; the
//! Rust expression is a typed error enum with the same vocabulary.

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QemuError {
    #[error("GenericError: {0}")]
    Generic(String),
    #[error("InvalidParameter: {0}")]
    InvalidParameter(String),
    #[error("DeviceNotFound: {0}")]
    DeviceNotFound(String),
    #[error("Unsupported: {0}")]
    Unsupported(String),
}

pub type QemuResult<T> = Result<T, QemuError>;

/// error_setg equivalent.
pub fn error_setg<T: Into<String>>(msg: T) -> QemuError {
    QemuError::Generic(msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vocabulary() {
        assert!(matches!(error_setg("boom"), QemuError::Generic(_)));
        assert_eq!(
            QemuError::Unsupported("tcg pending".into()).to_string(),
            "Unsupported: tcg pending"
        );
    }
}
