//! Parity with upstream `digestCanonicalValue` on recorded vectors.

use rea_domain::json::canonical_digest;
use serde_json::Value;

#[test]
fn canonical_digest_matches_upstream_vectors() {
    let text = include_str!("fixtures/canonical_digest_vectors.json");
    let vectors: Vec<Value> = serde_json::from_str(text).expect("valid fixture");
    assert!(vectors.len() > 30, "fixture lost its vectors");
    for vector in vectors {
        let value = &vector["value"];
        let expected = vector["digest"].as_str().expect("digest text");
        assert_eq!(
            canonical_digest(value).to_string(),
            expected,
            "value: {value}"
        );
    }
}
