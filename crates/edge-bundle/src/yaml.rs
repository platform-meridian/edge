//! YAML 1.2 documents as untyped values: only `true` and `false` are booleans.

use serde_json::Value;

/// The documents of a stream, empty ones skipped.
pub fn documents(text: &str) -> Result<Vec<Value>, serde_saphyr::Error> {
    serde_saphyr::from_multiple_with_options(text, serde_saphyr::options! { strict_booleans: true })
}

#[cfg(test)]
mod tests {
    #[test]
    fn yaml_1_1_booleans_stay_strings() {
        let d = super::documents("a: yes\nb: n\nc: true\n---\n---\nd: 1\n").unwrap();
        assert_eq!(
            d,
            [
                serde_json::json!({"a": "yes", "b": "n", "c": true}),
                serde_json::json!({"d": 1})
            ]
        );
    }
}
