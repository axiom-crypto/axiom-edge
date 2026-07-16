//! Program identifier used to select which ELF to prove against.
//!
//! Programs are identified by `(name, version)` end-to-end. `name` is a
//! user-friendly string chosen at registration time; `version` bumps each
//! time a new ELF is uploaded under the same name.
//!
//! The list of programs a deployment serves is operator-defined via the
//! `EDGE_PROGRAMS` environment variable (JSON array). Both the manager
//! and every worker parse the same env value on startup, so they agree
//! on the canonical loadout from boot. See [`parse_programs_env`].

use serde::{Deserialize, Serialize};

/// Environment variable name carrying the deployment's program loadout
/// as a JSON array of `{name, version}` objects.
pub const ENV_PROGRAMS: &str = "EDGE_PROGRAMS";

/// Identifies a single program version in the deployment loadout.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct ProgramRef {
    /// User-friendly program name (e.g. `"sha256"`).
    pub name: String,
    /// Monotonically increasing version, assigned per `name`.
    pub version: u32,
}

impl ProgramRef {
    pub fn new(name: impl Into<String>, version: u32) -> Self {
        Self {
            name: name.into(),
            version,
        }
    }
}

impl std::fmt::Display for ProgramRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@v{}", self.name, self.version)
    }
}

/// Error from parsing the `EDGE_PROGRAMS` env var.
#[derive(Debug)]
pub enum ParseProgramsError {
    /// The env variable is not set or is empty.
    Missing,
    /// The env variable did not parse as a JSON array of `ProgramRef`.
    InvalidJson(String),
    /// The program list is empty.
    Empty,
    /// Two entries share the same `(name, version)`.
    Duplicate(ProgramRef),
}

impl std::fmt::Display for ParseProgramsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(
                f,
                "{ENV_PROGRAMS} is not set; expected a JSON array of {{name, version}} objects"
            ),
            Self::InvalidJson(e) => write!(f, "{ENV_PROGRAMS} is not valid JSON: {e}"),
            Self::Empty => write!(f, "{ENV_PROGRAMS} must contain at least one program"),
            Self::Duplicate(p) => write!(f, "{ENV_PROGRAMS} contains duplicate program {p}"),
        }
    }
}

impl std::error::Error for ParseProgramsError {}

/// Parse `EDGE_PROGRAMS` from a raw JSON string.
///
/// Validates that the list is non-empty and that no `(name, version)`
/// pair is duplicated. Returns the programs in declaration order.
pub fn parse_programs_str(raw: &str) -> Result<Vec<ProgramRef>, ParseProgramsError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ParseProgramsError::Missing);
    }
    let programs: Vec<ProgramRef> = serde_json::from_str(trimmed)
        .map_err(|e| ParseProgramsError::InvalidJson(e.to_string()))?;
    if programs.is_empty() {
        return Err(ParseProgramsError::Empty);
    }
    let mut seen = std::collections::HashSet::new();
    for p in &programs {
        if !seen.insert(p.clone()) {
            return Err(ParseProgramsError::Duplicate(p.clone()));
        }
    }
    Ok(programs)
}

/// Parse `EDGE_PROGRAMS` directly from the process environment.
///
/// Returns `Err(ParseProgramsError::Missing)` if the variable is unset
/// or empty.
pub fn parse_programs_env() -> Result<Vec<ProgramRef>, ParseProgramsError> {
    match std::env::var(ENV_PROGRAMS) {
        Ok(s) => parse_programs_str(&s),
        Err(_) => Err(ParseProgramsError::Missing),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_basic_list() {
        let raw = r#"[{"name":"sha256","version":1},{"name":"keccak","version":2}]"#;
        let parsed = parse_programs_str(raw).unwrap();
        assert_eq!(
            parsed,
            vec![ProgramRef::new("sha256", 1), ProgramRef::new("keccak", 2),]
        );
    }

    #[test]
    fn ignores_surrounding_whitespace() {
        let raw = "  [ {\"name\":\"a\",\"version\":1} ]  ";
        let parsed = parse_programs_str(raw).unwrap();
        assert_eq!(parsed, vec![ProgramRef::new("a", 1)]);
    }

    #[test]
    fn rejects_empty_string() {
        assert!(matches!(
            parse_programs_str(""),
            Err(ParseProgramsError::Missing)
        ));
        assert!(matches!(
            parse_programs_str("   "),
            Err(ParseProgramsError::Missing)
        ));
    }

    #[test]
    fn rejects_empty_list() {
        assert!(matches!(
            parse_programs_str("[]"),
            Err(ParseProgramsError::Empty)
        ));
    }

    #[test]
    fn rejects_duplicate() {
        let raw = r#"[{"name":"a","version":1},{"name":"a","version":1}]"#;
        match parse_programs_str(raw) {
            Err(ParseProgramsError::Duplicate(p)) => {
                assert_eq!(p, ProgramRef::new("a", 1));
            }
            other => panic!("expected Duplicate, got {other:?}"),
        }
    }

    #[test]
    fn allows_same_name_different_version() {
        let raw = r#"[{"name":"a","version":1},{"name":"a","version":2}]"#;
        let parsed = parse_programs_str(raw).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(matches!(
            parse_programs_str("not json"),
            Err(ParseProgramsError::InvalidJson(_))
        ));
    }
}
