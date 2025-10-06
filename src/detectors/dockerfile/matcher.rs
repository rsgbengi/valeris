//! Rule matching logic for Dockerfile instructions.
//!
//! This module handles the evaluation of YAML rules against Dockerfile instructions,
//! supporting various matching strategies including equals, regex, glob, and composite matches.

use crate::detectors::dockerfile::yaml_rules::{Matcher, Predicate};
use serde_yml::Value;
use std::collections::HashMap;

/// Evaluates whether an instruction context matches a rule's matcher.
///
/// The matcher can specify multiple conditions using `all` (AND), `any` (OR),
/// or direct field comparisons.
///
/// # Arguments
///
/// * `matcher` - The rule's matching criteria
/// * `context` - Key-value map extracted from the instruction
///
/// # Returns
///
/// `true` if the instruction matches the matcher's conditions
pub fn matches_matcher(matcher: &Matcher, context: &HashMap<String, Value>) -> bool {
    // Check all predicates (AND logic)
    if let Some(all) = &matcher.all {
        if !all.iter().all(|p| matches_predicate(p, context)) {
            return false;
        }
    }

    // Check any predicates (OR logic)
    if let Some(any) = &matcher.any {
        if !any.iter().any(|p| matches_predicate(p, context)) {
            return false;
        }
    }

    // Direct field checks on matcher itself
    if let Some(field) = &matcher.field {
        let equals_value = matcher.equals.as_ref().map(|s| Value::String(s.clone()));
        return matches_field_conditions(
            field,
            context,
            equals_value.as_ref(),
            matcher.regex.as_ref(),
            matcher.glob.as_ref(),
            matcher.missing
        );
    }

    true
}

/// Evaluates a single predicate against the context.
///
/// # Arguments
///
/// * `pred` - The predicate to evaluate
/// * `context` - Key-value map from the instruction
///
/// # Returns
///
/// `true` if the predicate matches
fn matches_predicate(pred: &Predicate, context: &HashMap<String, Value>) -> bool {
    if let Some(field) = &pred.field {
        return matches_field_conditions(
            field,
            context,
            pred.equals.as_ref(),
            pred.regex.as_ref(),
            pred.glob.as_ref(),
            pred.missing
        );
    }
    true
}

/// Checks if a field satisfies the specified conditions.
///
/// Supports multiple matching strategies:
/// - `missing`: checks if field is absent
/// - `equals`: exact value comparison
/// - `regex`: pattern matching
/// - `glob`: wildcard matching
///
/// # Arguments
///
/// * `field` - The field name to check
/// * `context` - The instruction's data
/// * `equals` - Expected exact value (optional)
/// * `regex` - Compiled regex pattern (optional)
/// * `glob` - Glob pattern (optional)
/// * `missing` - Whether field should be absent (optional)
///
/// # Returns
///
/// `true` if the field satisfies all specified conditions
fn matches_field_conditions(
    field: &str,
    context: &HashMap<String, Value>,
    equals: Option<&Value>,
    regex: Option<&regex::Regex>,
    glob: Option<&String>,
    missing: Option<bool>,
) -> bool {
    let value = context.get(field);

    // Check missing condition
    if let Some(should_be_missing) = missing {
        return value.is_none() == should_be_missing;
    }

    // If no value and not checking for missing, no match
    let Some(value) = value else {
        return false;
    };

    // Check equals
    if let Some(expected) = equals {
        return value == expected;
    }

    // Check regex
    if let Some(re) = regex {
        if let Value::String(s) = value {
            return re.is_match(s);
        }
        return false;
    }

    // Check glob
    if let Some(pattern) = glob {
        if let Value::String(s) = value {
            return glob_match(pattern, s);
        }
        return false;
    }

    true
}

/// Performs glob-style pattern matching.
///
/// Converts glob patterns to regex:
/// - `*` matches any sequence of characters
/// - `?` matches a single character
/// - `.` is treated as a literal dot
///
/// # Arguments
///
/// * `pattern` - Glob pattern (e.g., "*.txt", "file??.log")
/// * `text` - Text to match against
///
/// # Returns
///
/// `true` if the text matches the glob pattern
fn glob_match(pattern: &str, text: &str) -> bool {
    let regex_pattern = pattern
        .replace(".", "\\.")
        .replace("*", ".*")
        .replace("?", ".");

    regex::Regex::new(&format!("^{}$", regex_pattern))
        .map(|re| re.is_match(text))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match_wildcard() {
        assert!(glob_match("*.txt", "file.txt"));
        assert!(glob_match("test*", "test123"));
        assert!(!glob_match("*.txt", "file.doc"));
    }

    #[test]
    fn test_glob_match_question_mark() {
        assert!(glob_match("file?.txt", "file1.txt"));
        assert!(glob_match("file?.txt", "fileX.txt"));
        assert!(!glob_match("file?.txt", "file12.txt"));
    }

    #[test]
    fn test_glob_match_literal_dot() {
        assert!(glob_match("file.txt", "file.txt"));
        assert!(!glob_match("file.txt", "fileXtxt"));
    }

    #[test]
    fn test_matches_field_conditions_equals() {
        let mut context = HashMap::new();
        context.insert("user".to_string(), Value::String("root".to_string()));

        let result = matches_field_conditions(
            "user",
            &context,
            Some(&Value::String("root".to_string())),
            None,
            None,
            None,
        );

        assert!(result);
    }

    #[test]
    fn test_matches_field_conditions_equals_mismatch() {
        let mut context = HashMap::new();
        context.insert("user".to_string(), Value::String("nobody".to_string()));

        let result = matches_field_conditions(
            "user",
            &context,
            Some(&Value::String("root".to_string())),
            None,
            None,
            None,
        );

        assert!(!result);
    }

    #[test]
    fn test_matches_field_conditions_regex() {
        let mut context = HashMap::new();
        context.insert("port".to_string(), Value::String("22".to_string()));

        let regex = regex::Regex::new("^(22|3306|5432)$").unwrap();
        let result = matches_field_conditions(
            "port",
            &context,
            None,
            Some(&regex),
            None,
            None,
        );

        assert!(result);
    }

    #[test]
    fn test_matches_field_conditions_regex_no_match() {
        let mut context = HashMap::new();
        context.insert("port".to_string(), Value::String("8080".to_string()));

        let regex = regex::Regex::new("^(22|3306|5432)$").unwrap();
        let result = matches_field_conditions(
            "port",
            &context,
            None,
            Some(&regex),
            None,
            None,
        );

        assert!(!result);
    }

    #[test]
    fn test_matches_field_conditions_missing_true() {
        let context = HashMap::new();

        let result = matches_field_conditions(
            "some_field",
            &context,
            None,
            None,
            None,
            Some(true), // Field should be missing
        );

        assert!(result);
    }

    #[test]
    fn test_matches_field_conditions_missing_false() {
        let mut context = HashMap::new();
        context.insert("field".to_string(), Value::String("value".to_string()));

        let result = matches_field_conditions(
            "field",
            &context,
            None,
            None,
            None,
            Some(true), // Field should be missing but it's present
        );

        assert!(!result);
    }

    #[test]
    fn test_matches_matcher_with_field_equals() {
        use crate::detectors::dockerfile::yaml_rules::Matcher;

        let mut context = HashMap::new();
        context.insert("user".to_string(), Value::String("root".to_string()));

        let matcher = Matcher {
            all: None,
            any: None,
            field: Some("user".to_string()),
            equals: Some("root".to_string()),
            regex: None,
            glob: None,
            missing: None,
        };

        assert!(matches_matcher(&matcher, &context));
    }

    #[test]
    fn test_matches_matcher_with_all_predicates() {
        use crate::detectors::dockerfile::yaml_rules::{Matcher, Predicate};

        let mut context = HashMap::new();
        context.insert("user".to_string(), Value::String("root".to_string()));
        context.insert("status".to_string(), Value::String("running".to_string()));

        let matcher = Matcher {
            all: Some(vec![
                Predicate {
                    field: Some("user".to_string()),
                    equals: Some(Value::String("root".to_string())),
                    regex: None,
                    glob: None,
                    missing: None,
                },
                Predicate {
                    field: Some("status".to_string()),
                    equals: Some(Value::String("running".to_string())),
                    regex: None,
                    glob: None,
                    missing: None,
                },
            ]),
            any: None,
            field: None,
            equals: None,
            regex: None,
            glob: None,
            missing: None,
        };

        assert!(matches_matcher(&matcher, &context));
    }

    #[test]
    fn test_matches_matcher_with_any_predicates() {
        use crate::detectors::dockerfile::yaml_rules::{Matcher, Predicate};

        let mut context = HashMap::new();
        context.insert("port".to_string(), Value::String("22".to_string()));

        let matcher = Matcher {
            all: None,
            any: Some(vec![
                Predicate {
                    field: Some("port".to_string()),
                    equals: Some(Value::String("22".to_string())),
                    regex: None,
                    glob: None,
                    missing: None,
                },
                Predicate {
                    field: Some("port".to_string()),
                    equals: Some(Value::String("3306".to_string())),
                    regex: None,
                    glob: None,
                    missing: None,
                },
            ]),
            field: None,
            equals: None,
            regex: None,
            glob: None,
            missing: None,
        };

        assert!(matches_matcher(&matcher, &context));
    }
}
