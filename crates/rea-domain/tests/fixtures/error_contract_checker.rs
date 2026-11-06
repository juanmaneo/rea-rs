//! Shared test support: a validator for the JSON Schema keywords
//! `error_contract.schema.json` uses (copied from
//! `upstream:docs/error-contract.schema.json`), and a projection helper that
//! validates every value it returns. Unknown keywords or patterns panic, so a
//! schema change cannot silently weaken the check.

// Each including test crate uses a different subset of these helpers, and
// clippy's in-test allowances do not reach helpers outside `#[test]` items.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::OnceLock;

use rea_domain::error::{AnalysisError, CallerLifetime};
use serde_json::{Map, Value};

const SCHEMA_TEXT: &str = include_str!("error_contract.schema.json");

/// The parsed contract schema.
pub fn schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| serde_json::from_str(SCHEMA_TEXT).expect("schema fixture is JSON"))
}

/// Validate `value` against the contract schema.
pub fn validate(value: &Value) -> Result<(), String> {
    let root = schema();
    assert_eq!(
        root.get("$schema").and_then(Value::as_str),
        Some("https://json-schema.org/draft/2020-12/schema"),
        "unexpected schema dialect"
    );
    check(root, value, "$")
}

/// Project `error` for `lifetime` and require the result to satisfy the contract.
pub fn project(error: &AnalysisError, lifetime: CallerLifetime) -> Value {
    let projected = error.project(lifetime).to_value();
    if let Err(problem) = validate(&projected) {
        panic!("projection violates the error contract: {problem}\n{projected:#}");
    }
    projected
}

/// [`project`] for a continuing caller.
pub fn continuing(error: &AnalysisError) -> Value {
    project(error, CallerLifetime::Continuing)
}

/// [`project`] for an invocation caller.
pub fn invocation(error: &AnalysisError) -> Value {
    project(error, CallerLifetime::Invocation)
}

/// The members of a JSON object literal.
pub fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(members) => members,
        other => panic!("expected a JSON object, got {other}"),
    }
}

/// `value` with the member at JSON `pointer` replaced.
pub fn replaced(mut value: Value, pointer: &str, replacement: Value) -> Value {
    *value.pointer_mut(pointer).expect("pointer exists") = replacement;
    value
}

/// `value`, an object, without member `key`.
pub fn without(mut value: Value, key: &str) -> Value {
    value.as_object_mut().expect("object").remove(key);
    value
}

/// Vitest `toMatchObject`: every member of `expected` is present in `actual`
/// and matches recursively; arrays match element-wise with equal length.
pub fn assert_matches(actual: &Value, expected: &Value) {
    if let Err(problem) = matches(actual, expected, "$") {
        panic!("{problem}\nactual: {actual:#}\nexpected subset: {expected:#}");
    }
}

fn matches(actual: &Value, expected: &Value, at: &str) -> Result<(), String> {
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => {
            for (key, expected) in expected {
                let member = actual
                    .get(key)
                    .ok_or_else(|| format!("{at}.{key} is missing"))?;
                matches(member, expected, &format!("{at}.{key}"))?;
            }
            Ok(())
        }
        (Value::Array(actual), Value::Array(expected)) => {
            if actual.len() != expected.len() {
                return Err(format!(
                    "{at} has {} items, expected {}",
                    actual.len(),
                    expected.len()
                ));
            }
            for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
                matches(actual, expected, &format!("{at}[{index}]"))?;
            }
            Ok(())
        }
        _ if actual == expected => Ok(()),
        _ => Err(format!("{at} is {actual}, expected {expected}")),
    }
}

fn check(schema: &Value, value: &Value, at: &str) -> Result<(), String> {
    let Value::Object(schema) = schema else {
        panic!("schema at {at} is not an object");
    };
    for (keyword, argument) in schema {
        match keyword.as_str() {
            "$schema" | "properties" | "additionalProperties" => {}
            "oneOf" => {
                let passing = branches(argument)
                    .filter(|branch| check(branch, value, at).is_ok())
                    .count();
                if passing != 1 {
                    return Err(format!("{at} matches {passing} oneOf branches"));
                }
            }
            "anyOf" => {
                if !branches(argument).any(|branch| check(branch, value, at).is_ok()) {
                    return Err(format!("{at} matches no anyOf branch"));
                }
            }
            "const" => {
                if value != argument {
                    return Err(format!("{at} is {value}, expected const {argument}"));
                }
            }
            "enum" => {
                if !branches(argument).any(|allowed| allowed == value) {
                    return Err(format!("{at} value {value} is not in enum"));
                }
            }
            "type" => {
                let accepted = match argument {
                    Value::String(name) => has_type(value, name),
                    Value::Array(names) => names
                        .iter()
                        .any(|name| has_type(value, name.as_str().expect("type name"))),
                    other => panic!("unsupported type argument {other}"),
                };
                if !accepted {
                    return Err(format!("{at} value {value} is not of type {argument}"));
                }
            }
            "required" => {
                if let Value::Object(members) = value {
                    for name in branches(argument) {
                        let name = name.as_str().expect("required name");
                        if !members.contains_key(name) {
                            return Err(format!("{at}.{name} is required"));
                        }
                    }
                }
            }
            "propertyNames" => {
                if let Value::Object(members) = value {
                    for name in members.keys() {
                        check(
                            argument,
                            &Value::String(name.clone()),
                            &format!("{at}[key {name}]"),
                        )?;
                    }
                }
            }
            "minLength" => {
                let minimum = argument.as_u64().expect("minLength");
                if let Value::String(text) = value
                    && (text.chars().count() as u64) < minimum
                {
                    return Err(format!("{at} is shorter than {minimum}"));
                }
            }
            "exclusiveMinimum" => {
                let bound = argument.as_f64().expect("exclusiveMinimum");
                if let Some(number) = value.as_f64()
                    && number <= bound
                {
                    return Err(format!("{at} {number} is not greater than {bound}"));
                }
            }
            "maximum" => {
                let bound = argument.as_f64().expect("maximum");
                if let Some(number) = value.as_f64()
                    && number > bound
                {
                    return Err(format!("{at} {number} exceeds {bound}"));
                }
            }
            "pattern" => {
                let pattern = argument.as_str().expect("pattern");
                if let Value::String(text) = value
                    && !matches_hex_pattern(pattern, text)
                {
                    return Err(format!("{at} {text:?} does not match {pattern}"));
                }
            }
            other => panic!("unsupported schema keyword {other} at {at}"),
        }
    }
    if let Value::Object(members) = value {
        check_members(schema, members, at)?;
    }
    Ok(())
}

fn check_members(
    schema: &Map<String, Value>,
    members: &Map<String, Value>,
    at: &str,
) -> Result<(), String> {
    let properties = schema.get("properties").and_then(Value::as_object);
    for (name, member) in members {
        let path = format!("{at}.{name}");
        match properties.and_then(|properties| properties.get(name)) {
            Some(property) => check(property, member, &path)?,
            None => match schema.get("additionalProperties") {
                None => {}
                Some(Value::Bool(true)) => {}
                Some(Value::Bool(false)) => return Err(format!("{path} is not allowed")),
                Some(additional) => check(additional, member, &path)?,
            },
        }
    }
    Ok(())
}

fn branches(argument: &Value) -> impl Iterator<Item = &Value> {
    argument.as_array().expect("array keyword argument").iter()
}

fn has_type(value: &Value, name: &str) -> bool {
    match name {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "integer" => {
            value.is_u64() || value.is_i64() || value.as_f64().is_some_and(|n| n.fract() == 0.0)
        }
        other => panic!("unsupported type {other}"),
    }
}

/// Only the `^[a-f0-9]{N}$` patterns the schema uses are supported.
fn matches_hex_pattern(pattern: &str, text: &str) -> bool {
    let length: usize = pattern
        .strip_prefix("^[a-f0-9]{")
        .and_then(|rest| rest.strip_suffix("}$"))
        .and_then(|length| length.parse().ok())
        .unwrap_or_else(|| panic!("unsupported pattern {pattern}"));
    text.len() == length
        && text
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'f' | b'0'..=b'9'))
}
