//! Raw caller arguments parsed into typed tool inputs.
//!
//! Each tool input owns one parser built from [`InputObject`]. Issues follow
//! upstream's zod projection (`upstream:src/domain/inputIssueProjection.ts`):
//! members are checked in schema shape order, then unknown members are
//! reported in caller order.
//!
//! Upstream reference: `upstream:src/application/AnalysisInput.ts` and
//! `upstream:src/domain/localPath.ts`.

use serde_json::{Map, Number, Value};

use crate::error::{InputIssue, InputIssueReason};

/// Message for a local path containing NUL (`nulFreeStringSchema`).
pub const NUL_PATH_MESSAGE: &str = "Local filesystem paths cannot contain NUL";

/// A strict JSON object of caller arguments being parsed member by member.
#[derive(Debug)]
pub struct InputObject<'a> {
    members: &'a Map<String, Value>,
    known: Vec<&'static str>,
    issues: Vec<InputIssue>,
}

impl<'a> InputObject<'a> {
    /// Start parsing `input`, which must be a JSON object.
    pub fn new(input: Option<&'a Value>) -> Result<Self, Vec<InputIssue>> {
        match input {
            Some(Value::Object(members)) => Ok(Self {
                members,
                known: Vec::new(),
                issues: Vec::new(),
            }),
            Some(_) => Err(vec![type_issue(
                Vec::<String>::new(),
                InputIssueReason::InvalidType,
                "object",
            )]),
            None => Err(vec![type_issue(
                Vec::<String>::new(),
                InputIssueReason::MissingArgument,
                "object",
            )]),
        }
    }

    fn member(&mut self, key: &'static str) -> Option<&'a Value> {
        self.known.push(key);
        self.members.get(key)
    }

    /// A required, nonempty, NUL-free local filesystem path
    /// (`localPathStringSchema`).
    pub fn local_path(&mut self, key: &'static str) -> Option<String> {
        let text = match self.member(key) {
            None => {
                self.issues.push(type_issue(
                    [key],
                    InputIssueReason::MissingArgument,
                    "string",
                ));
                return None;
            }
            Some(Value::String(text)) => text,
            Some(_) => {
                self.issues
                    .push(type_issue([key], InputIssueReason::InvalidType, "string"));
                return None;
            }
        };
        if text.contains('\0') {
            self.issues.push(
                InputIssue::new([key], InputIssueReason::InvalidFormat)
                    .with_expected("regex")
                    .with_message(NUL_PATH_MESSAGE),
            );
            return None;
        }
        if text.is_empty() {
            self.issues.push(
                InputIssue::new([key], InputIssueReason::OutOfRange)
                    .with_range(Some(Number::from(1_u64)), None),
            );
            return None;
        }
        Some(text.clone())
    }

    /// An optional integer within `minimum..=maximum`, or `default` when absent.
    pub fn integer(
        &mut self,
        key: &'static str,
        minimum: u64,
        maximum: u64,
        default: u64,
    ) -> Option<u64> {
        let number = match self.member(key) {
            None => return Some(default),
            Some(Value::Number(number)) => number,
            Some(_) => {
                self.issues
                    .push(type_issue([key], InputIssueReason::InvalidType, "number"));
                return None;
            }
        };
        let below = || {
            InputIssue::new([key], InputIssueReason::OutOfRange)
                .with_range(Some(Number::from(minimum)), None)
        };
        let above = || {
            InputIssue::new([key], InputIssueReason::OutOfRange)
                .with_range(None, Some(Number::from(maximum)))
        };
        let value = if let Some(value) = number.as_u64() {
            value
        } else if number.as_i64().is_some() {
            self.issues.push(below());
            return None;
        } else {
            // JSON numbers outside the integer types arrive as `f64`.
            let float = number.as_f64().unwrap_or(f64::NAN);
            if !float.is_finite() || float.fract() != 0.0 {
                self.issues
                    .push(type_issue([key], InputIssueReason::InvalidType, "int"));
                return None;
            }
            if float < 0.0 {
                self.issues.push(below());
                return None;
            }
            if float > maximum as f64 {
                self.issues.push(above());
                return None;
            }
            // Integral, non-negative, and at most `maximum`.
            float as u64
        };
        if value < minimum {
            self.issues.push(below());
            None
        } else if value > maximum {
            self.issues.push(above());
            None
        } else {
            Some(value)
        }
    }

    /// Report unknown members and return every issue, or `Ok` when none.
    pub fn finish(mut self) -> Result<(), Vec<InputIssue>> {
        for key in self.members.keys() {
            if !self.known.contains(&key.as_str()) {
                self.issues.push(InputIssue::new(
                    [key.as_str()],
                    InputIssueReason::UnknownArgument,
                ));
            }
        }
        if self.issues.is_empty() {
            Ok(())
        } else {
            Err(self.issues)
        }
    }
}

fn type_issue<P, S>(path: P, reason: InputIssueReason, expected: &str) -> InputIssue
where
    P: IntoIterator<Item = S>,
    S: Into<crate::error::IssuePathSegment>,
{
    InputIssue::new(path, reason).with_expected(expected)
}
