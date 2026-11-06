//! JSON text compatible with upstream REA's JavaScript serialization.
//!
//! Two owners live here:
//!
//! * [`canonical_digest`] hashes canonical JSON (RFC 8785 member ordering by
//!   UTF-16 code units, `JSON.stringify` escaping and ECMAScript number text).
//!   Evidence identifiers commit to these exact bytes, so they must match
//!   upstream's `digestCanonicalValue` byte for byte.
//! * [`write_json`] writes caller-facing output in member insertion order,
//!   compact or indented by two spaces like `JSON.stringify(value, null, 2)`.
//!
//! Upstream reference: `upstream:src/domain/canonicalDigest.ts` and
//! `upstream:src/domain/jsonSerialization.ts`.

use std::cmp::Ordering;
use std::io::{self, Write};

use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};

use crate::digest::Sha256Digest;

/// Largest integer JavaScript represents exactly (`Number.MAX_SAFE_INTEGER`).
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// SHA-256 of the canonical JSON text of `value`.
pub fn canonical_digest(value: &Value) -> Sha256Digest {
    let mut hasher = HashWriter(Sha256::new());
    // Writing into a hasher cannot fail.
    let _ = write_canonical(value, &mut hasher);
    Sha256Digest::finish(hasher.0)
}

/// Write the canonical JSON text of `value`.
pub fn write_canonical<W: Write>(value: &Value, out: &mut W) -> io::Result<()> {
    match value {
        Value::Array(items) => {
            out.write_all(b"[")?;
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.write_all(b",")?;
                }
                write_canonical(item, out)?;
            }
            out.write_all(b"]")
        }
        Value::Object(members) => {
            let mut sorted: Vec<(&String, &Value)> = members.iter().collect();
            sorted.sort_by(|(left, _), (right, _)| compare_utf16(left, right));
            out.write_all(b"{")?;
            for (index, (key, item)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.write_all(b",")?;
                }
                write_string(key, out)?;
                out.write_all(b":")?;
                write_canonical(item, out)?;
            }
            out.write_all(b"}")
        }
        scalar => write_scalar(scalar, out),
    }
}

/// Compare strings by UTF-16 code units, the order JavaScript's default sort uses.
pub fn compare_utf16(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

/// Output layout for [`write_json`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonLayout {
    /// No insignificant whitespace; used for pipes, files, and agents.
    Compact,
    /// Two-space indentation for a terminal reader.
    Pretty,
}

/// Write `value` in member insertion order with JavaScript number text.
pub fn write_json<W: Write>(value: &Value, layout: JsonLayout, out: &mut W) -> io::Result<()> {
    write_json_at(value, layout, 0, out)
}

/// Render `value` to a string; see [`write_json`].
pub fn to_json_string(value: &Value, layout: JsonLayout) -> String {
    let mut buffer = Vec::new();
    // Writing into a Vec cannot fail, and every fragment written is UTF-8.
    let _ = write_json(value, layout, &mut buffer);
    String::from_utf8_lossy(&buffer).into_owned()
}

fn write_json_at<W: Write>(
    value: &Value,
    layout: JsonLayout,
    depth: usize,
    out: &mut W,
) -> io::Result<()> {
    match value {
        Value::Array(items) if items.is_empty() => out.write_all(b"[]"),
        Value::Object(members) if members.is_empty() => out.write_all(b"{}"),
        Value::Array(items) => {
            out.write_all(b"[")?;
            for (index, item) in items.iter().enumerate() {
                separator(index, layout, depth + 1, out)?;
                write_json_at(item, layout, depth + 1, out)?;
            }
            close(layout, depth, out)?;
            out.write_all(b"]")
        }
        Value::Object(members) => write_object(members, layout, depth, out),
        scalar => write_scalar(scalar, out),
    }
}

fn write_object<W: Write>(
    members: &Map<String, Value>,
    layout: JsonLayout,
    depth: usize,
    out: &mut W,
) -> io::Result<()> {
    out.write_all(b"{")?;
    for (index, (key, item)) in members.iter().enumerate() {
        separator(index, layout, depth + 1, out)?;
        write_string(key, out)?;
        out.write_all(match layout {
            JsonLayout::Compact => b":",
            JsonLayout::Pretty => b": ",
        })?;
        write_json_at(item, layout, depth + 1, out)?;
    }
    close(layout, depth, out)?;
    out.write_all(b"}")
}

fn separator<W: Write>(
    index: usize,
    layout: JsonLayout,
    depth: usize,
    out: &mut W,
) -> io::Result<()> {
    if index > 0 {
        out.write_all(b",")?;
    }
    if layout == JsonLayout::Pretty {
        out.write_all(b"\n")?;
        indent(depth, out)?;
    }
    Ok(())
}

fn close<W: Write>(layout: JsonLayout, depth: usize, out: &mut W) -> io::Result<()> {
    if layout == JsonLayout::Pretty {
        out.write_all(b"\n")?;
        indent(depth, out)?;
    }
    Ok(())
}

fn indent<W: Write>(depth: usize, out: &mut W) -> io::Result<()> {
    for _ in 0..depth {
        out.write_all(b"  ")?;
    }
    Ok(())
}

fn write_scalar<W: Write>(value: &Value, out: &mut W) -> io::Result<()> {
    match value {
        Value::Null => out.write_all(b"null"),
        Value::Bool(true) => out.write_all(b"true"),
        Value::Bool(false) => out.write_all(b"false"),
        Value::Number(number) => out.write_all(js_number_text(number).as_bytes()),
        Value::String(text) => write_string(text, out),
        Value::Array(_) | Value::Object(_) => write_canonical(value, out),
    }
}

/// `JSON.stringify` string escaping. serde_json applies the same rules: it
/// escapes `"`, `\`, and C0 controls (short forms for `\b\f\n\r\t`, lowercase
/// `\u00xx` otherwise) and leaves all other code points, including U+2028 and
/// U+2029, unescaped. Rust strings cannot hold lone surrogates.
fn write_string<W: Write>(text: &str, out: &mut W) -> io::Result<()> {
    serde_json::to_writer(out, text).map_err(io::Error::other)
}

/// ECMAScript `Number::toString` text for a JSON number.
///
/// Integers beyond `Number.MAX_SAFE_INTEGER` are rendered as the nearest
/// double, which is what a JavaScript producer would have observed.
pub fn js_number_text(number: &Number) -> String {
    if let Some(value) = number.as_u64().filter(|value| *value <= MAX_SAFE_INTEGER) {
        return value.to_string();
    }
    if let Some(value) = number
        .as_i64()
        .filter(|value| value.unsigned_abs() <= MAX_SAFE_INTEGER)
    {
        return value.to_string();
    }
    // serde_json numbers are always finite.
    js_float_text(number.as_f64().unwrap_or(0.0))
}

/// ECMAScript `Number::toString(x)` for a finite double (ECMA-262 §6.1.6.1.20).
pub fn js_float_text(value: f64) -> String {
    if value == 0.0 {
        return "0".to_owned();
    }
    if !value.is_finite() {
        // Non-finite numbers are not JSON; JSON.stringify emits null.
        return "null".to_owned();
    }
    let (digits, exponent) = shortest_digits(value.abs());
    let sign = if value < 0.0 { "-" } else { "" };
    let k = digits.len() as i32;
    let n = exponent;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        let (whole, fraction) = digits.split_at(n as usize);
        format!("{whole}.{fraction}")
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let exponent_sign = if e < 0 { '-' } else { '+' };
        let (first, rest) = digits.split_at(1);
        if rest.is_empty() {
            format!("{first}e{exponent_sign}{}", e.unsigned_abs())
        } else {
            format!("{first}.{rest}e{exponent_sign}{}", e.unsigned_abs())
        }
    };
    format!("{sign}{body}")
}

/// Shortest round-trip decimal digits `s` and exponent `n` with
/// `value = 0.s × 10^n` (no leading or trailing zeros in `s`).
fn shortest_digits(value: f64) -> (String, i32) {
    let mut buffer = ryu::Buffer::new();
    let text = buffer.format_finite(value);
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().unwrap_or(0)),
        None => (text, 0),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let mut digits: String = whole.chars().chain(fraction.chars()).collect();
    let mut point = whole.len() as i32 + exponent;
    let leading = digits.len() - digits.trim_start_matches('0').len();
    digits.drain(..leading);
    point -= leading as i32;
    let trimmed = digits.trim_end_matches('0').len();
    digits.truncate(trimmed);
    (digits, point)
}

struct HashWriter(Sha256);

impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canonical(value: &Value) -> String {
        let mut out = Vec::new();
        write_canonical(value, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn numbers_follow_ecmascript_text() {
        let cases: [(f64, &str); 16] = [
            (1e30, "1e+30"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (123.0, "123"),
            (0.1, "0.1"),
            (-0.0, "0"),
            (1.5e-7, "1.5e-7"),
            (0.000001, "0.000001"),
            (1e-7, "1e-7"),
            (123.456, "123.456"),
            (-2.5, "-2.5"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (2f64.powi(53), "9007199254740992"),
            (0.30000000000000004, "0.30000000000000004"),
            (1234567.0e15, "1.234567e+21"),
        ];
        for (value, expected) in cases {
            assert_eq!(js_float_text(value), expected, "{value:e}");
        }
        assert_eq!(
            js_number_text(&Number::from(u64::MAX)),
            "18446744073709552000"
        );
        assert_eq!(js_number_text(&Number::from(-42i64)), "-42");
    }

    #[test]
    fn canonical_members_sort_by_utf16_code_units() {
        // U+E000 sorts after U+10000 in UTF-16 (0xD800 < 0xE000), unlike UTF-8.
        let value = json!({"\u{E000}": 1, "\u{10000}": 2, "b": [true, null], "a": "x"});
        assert_eq!(
            canonical(&value),
            "{\"a\":\"x\",\"b\":[true,null],\"\u{10000}\":2,\"\u{E000}\":1}"
        );
    }

    #[test]
    fn pretty_output_matches_json_stringify_indentation() {
        let value = json!({"b": [1, {"c": []}], "a": {}});
        assert_eq!(
            to_json_string(&value, JsonLayout::Pretty),
            "{\n  \"b\": [\n    1,\n    {\n      \"c\": []\n    }\n  ],\n  \"a\": {}\n}"
        );
        assert_eq!(
            to_json_string(&value, JsonLayout::Compact),
            "{\"b\":[1,{\"c\":[]}],\"a\":{}}"
        );
    }
}
