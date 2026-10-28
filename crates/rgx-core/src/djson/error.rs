// SPDX-License-Identifier: Apache-2.0

//! Enhanced JSON error types with detailed diagnostics.
//!
//! Provides serde_json-compatible error types with:
//! - Line and column information for syntax errors
//! - Error category classification
//! - Detailed error messages with context
//! - Support for both `no_std` and `std` environments

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use core::fmt;

/// JSON error category for classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Syntax error in JSON input
    Syntax,
    /// Invalid data type or value
    Data,
    /// EOF encountered unexpectedly
    Eof,
    /// IO error (std feature required)
    Io,
    /// Error during serialization
    Serialize,
    /// Error during deserialization
    Deserialize,
}

/// Enhanced JSON error with detailed diagnostics.
///
/// Provides line/column information, error category,
/// and context for better error reporting.
///
/// Uses `Box<String>` for large fields to keep the error type
/// small (under 64 bytes) for efficient Result handling.
#[derive(Debug, Clone)]
pub struct JsonError {
    /// Error category
    pub category: ErrorCategory,
    /// Human-readable error message
    pub message: Box<str>,
    /// Line number (1-indexed) where error occurred
    pub line: usize,
    /// Column number (1-indexed) where error occurred
    pub column: usize,
    /// Byte offset where error occurred
    pub byte_offset: usize,
    /// Expected token or value (for syntax errors)
    pub expected: Option<Box<str>>,
    /// Actual token or value encountered
    pub actual: Option<Box<str>>,
    /// Path to the error location in the JSON structure
    pub path: Option<Box<str>>,
}

impl JsonError {
    fn boxed_str(s: impl Into<String>) -> Box<str> {
        s.into().into_boxed_str()
    }

    /// Create a syntax error at a specific position.
    pub fn syntax(message: impl Into<String>, line: usize, column: usize) -> Self {
        Self {
            category: ErrorCategory::Syntax,
            message: Self::boxed_str(message),
            line,
            column,
            byte_offset: 0,
            expected: None,
            actual: None,
            path: None,
        }
    }

    /// Create a syntax error with expected/actual context.
    pub fn syntax_expected(
        message: impl Into<String>,
        line: usize,
        column: usize,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self {
            category: ErrorCategory::Syntax,
            message: Self::boxed_str(message),
            line,
            column,
            byte_offset: 0,
            expected: Some(Self::boxed_str(expected)),
            actual: Some(Self::boxed_str(actual)),
            path: None,
        }
    }

    /// Create an EOF error.
    pub fn eof(message: impl Into<String>, line: usize, column: usize) -> Self {
        Self {
            category: ErrorCategory::Eof,
            message: Self::boxed_str(message),
            line,
            column,
            byte_offset: 0,
            expected: None,
            actual: None,
            path: None,
        }
    }

    /// Create a data type error.
    pub fn data(message: impl Into<String>) -> Self {
        Self {
            category: ErrorCategory::Data,
            message: Self::boxed_str(message),
            line: 0,
            column: 0,
            byte_offset: 0,
            expected: None,
            actual: None,
            path: None,
        }
    }

    /// Create a data type error with path context.
    pub fn data_at(message: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            category: ErrorCategory::Data,
            message: Self::boxed_str(message),
            line: 0,
            column: 0,
            byte_offset: 0,
            expected: None,
            actual: None,
            path: Some(Self::boxed_str(path)),
        }
    }

    /// Create a serialization error.
    pub fn serialize(message: impl Into<String>) -> Self {
        Self {
            category: ErrorCategory::Serialize,
            message: Self::boxed_str(message),
            line: 0,
            column: 0,
            byte_offset: 0,
            expected: None,
            actual: None,
            path: None,
        }
    }

    /// Create a deserialization error.
    pub fn deserialize(message: impl Into<String>) -> Self {
        Self {
            category: ErrorCategory::Deserialize,
            message: Self::boxed_str(message),
            line: 0,
            column: 0,
            byte_offset: 0,
            expected: None,
            actual: None,
            path: None,
        }
    }

    /// Create a deserialization error with path context.
    pub fn deserialize_at(message: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            category: ErrorCategory::Deserialize,
            message: Self::boxed_str(message),
            line: 0,
            column: 0,
            byte_offset: 0,
            expected: None,
            actual: None,
            path: Some(Self::boxed_str(path)),
        }
    }

    /// Set the byte offset.
    pub fn with_byte_offset(self, offset: usize) -> Self {
        Self {
            byte_offset: offset,
            ..self
        }
    }

    /// Set the path context.
    pub fn with_path(self, path: impl Into<String>) -> Self {
        Self {
            path: Some(Self::boxed_str(path)),
            ..self
        }
    }

    /// Check if this is a syntax error.
    pub fn is_syntax(&self) -> bool {
        self.category == ErrorCategory::Syntax
    }

    /// Check if this is an EOF error.
    pub fn is_eof(&self) -> bool {
        self.category == ErrorCategory::Eof
    }

    /// Check if this is a data error.
    pub fn is_data(&self) -> bool {
        self.category == ErrorCategory::Data
    }

    /// Check if this is an IO error.
    pub fn is_io(&self) -> bool {
        self.category == ErrorCategory::Io
    }

    /// Get a formatted position string.
    pub fn position_string(&self) -> String {
        if self.line > 0 && self.column > 0 {
            format!("line {} column {}", self.line, self.column)
        } else if self.byte_offset > 0 {
            format!("byte {}", self.byte_offset)
        } else {
            String::from("unknown position")
        }
    }

    /// Get a formatted context string (expected vs actual).
    pub fn context_string(&self) -> Option<String> {
        match (&self.expected, &self.actual) {
            (Some(exp), Some(act)) => Some(format!("expected {}, found {}", exp, act)),
            (Some(exp), None) => Some(format!("expected {}", exp)),
            (None, Some(act)) => Some(format!("found {}", act)),
            (None, None) => None,
        }
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JSON error: {}", self.message)?;

        if self.line > 0 || self.byte_offset > 0 {
            write!(f, " at {}", self.position_string())?;
        }

        if let Some(ctx) = self.context_string() {
            write!(f, " ({})", ctx)?;
        }

        if let Some(path) = &self.path {
            write!(f, " in path '{}'", path)?;
        }

        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for JsonError {}

/// JSON parse result type.
pub type JsonResult<T> = Result<T, JsonError>;

// ═══════════════════════════════════════════════════════════════════════════════
// Conversion from legacy error types
// ═══════════════════════════════════════════════════════════════════════════════

impl From<super::parser::JsonParseError> for JsonError {
    fn from(e: super::parser::JsonParseError) -> Self {
        Self::syntax(e.message, e.line, e.col)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn test_syntax_error() {
        let err = JsonError::syntax("Unexpected character", 10, 5);
        assert_eq!(err.category, ErrorCategory::Syntax);
        assert_eq!(err.line, 10);
        assert_eq!(err.column, 5);
        assert!(err.is_syntax());
    }

    #[test]
    fn test_syntax_error_with_context() {
        let err = JsonError::syntax_expected("Expected value", 5, 10, "value", "']'");
        assert_eq!(err.expected.as_deref(), Some("value"));
        assert_eq!(err.actual.as_deref(), Some("']'"));
    }

    #[test]
    fn test_eof_error() {
        let err = JsonError::eof("Unexpected end of input", 15, 20);
        assert_eq!(err.category, ErrorCategory::Eof);
        assert!(err.is_eof());
    }

    #[test]
    fn test_data_error() {
        let err = JsonError::data("Invalid number");
        assert_eq!(err.category, ErrorCategory::Data);
        assert!(err.is_data());
    }

    #[test]
    fn test_error_display() {
        let err = JsonError::syntax_expected("Missing comma", 10, 5, "','", "'}'");
        let msg = err.to_string();
        assert!(msg.contains("line 10 column 5"));
        assert!(msg.contains("expected ','"));
        assert!(msg.contains("found '}'"));
    }

    #[test]
    fn test_error_with_path() {
        let err = JsonError::data_at("Type mismatch", "/data/items[0]/price");
        assert_eq!(err.path.as_deref(), Some("/data/items[0]/price"));
        let msg = err.to_string();
        assert!(msg.contains("in path '/data/items[0]/price'"));
    }

    #[test]
    fn test_position_string() {
        let err = JsonError::syntax("test", 5, 10);
        assert_eq!(err.position_string(), "line 5 column 10");

        let err = JsonError::data("test").with_byte_offset(123);
        assert_eq!(err.position_string(), "byte 123");

        let err = JsonError::data("test");
        assert_eq!(err.position_string(), "unknown position");
    }
}
