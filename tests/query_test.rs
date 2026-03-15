use gmail_proxy::scrub::query::{
    parse_query, reconstruct_query, reconstruct_with_label_exclusion, validate_query, QueryNode,
};

#[test]
fn test_parse_single_word() {
    let node = parse_query("hello").unwrap();
    assert_eq!(node, QueryNode::Term("hello".into()));
}

#[test]
fn test_parse_two_words_implicit_and() {
    let node = parse_query("hello world").unwrap();
    match node {
        QueryNode::And(children) => {
            assert_eq!(children.len(), 2);
            assert_eq!(children[0], QueryNode::Term("hello".into()));
            assert_eq!(children[1], QueryNode::Term("world".into()));
        }
        other => panic!("Expected And, got {other:?}"),
    }
}

#[test]
fn test_parse_quoted_string() {
    let node = parse_query(r#""hello world""#).unwrap();
    assert_eq!(node, QueryNode::Quoted("hello world".into()));
}

#[test]
fn test_parse_operator() {
    let node = parse_query("from:alice").unwrap();
    match node {
        QueryNode::Operator { key, value, negated } => {
            assert_eq!(key, "from");
            assert_eq!(value, "alice");
            assert!(!negated);
        }
        other => panic!("Expected Operator, got {other:?}"),
    }
}

#[test]
fn test_parse_negated_operator() {
    let node = parse_query("-from:bob").unwrap();
    match node {
        QueryNode::Operator { key, value, negated } => {
            assert_eq!(key, "from");
            assert_eq!(value, "bob");
            assert!(negated);
        }
        other => panic!("Expected negated Operator, got {other:?}"),
    }
}

#[test]
fn test_parse_operator_quoted_value() {
    let node = parse_query(r#"subject:"hello world""#).unwrap();
    match node {
        QueryNode::Operator { key, value, negated } => {
            assert_eq!(key, "subject");
            assert_eq!(value, "hello world");
            assert!(!negated);
        }
        other => panic!("Expected Operator, got {other:?}"),
    }
}

#[test]
fn test_parse_or_expression() {
    let node = parse_query("from:alice OR from:bob").unwrap();
    match node {
        QueryNode::Or(children) => {
            assert_eq!(children.len(), 2);
        }
        other => panic!("Expected Or, got {other:?}"),
    }
}

#[test]
fn test_parse_group_parens() {
    let node = parse_query("(from:alice OR from:bob) subject:meeting").unwrap();
    match node {
        QueryNode::And(children) => {
            assert_eq!(children.len(), 2);
            match &children[0] {
                QueryNode::Group(inner) => match inner.as_ref() {
                    QueryNode::Or(_) => {}
                    other => panic!("Expected Or inside group, got {other:?}"),
                },
                other => panic!("Expected Group, got {other:?}"),
            }
        }
        other => panic!("Expected And, got {other:?}"),
    }
}

#[test]
fn test_parse_negated_term() {
    let node = parse_query("-spam").unwrap();
    match node {
        QueryNode::Not(inner) => {
            assert_eq!(*inner, QueryNode::Term("spam".into()));
        }
        other => panic!("Expected Not, got {other:?}"),
    }
}

#[test]
fn test_parse_curly_brace_group() {
    let node = parse_query("{from:alice from:bob}").unwrap();
    match node {
        QueryNode::Group(inner) => match inner.as_ref() {
            QueryNode::And(_) => {}
            other => panic!("Expected And inside group, got {other:?}"),
        },
        other => panic!("Expected Group, got {other:?}"),
    }
}

#[test]
fn test_parse_empty_query() {
    let result = parse_query("");
    assert!(result.is_err());
}

#[test]
fn test_unmatched_open_paren() {
    let result = parse_query("(from:alice");
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.to_lowercase().contains("unmatched") || err.to_lowercase().contains("parenthesis"),
        "Error should mention unmatched paren: {err}"
    );
}

#[test]
fn test_unmatched_close_paren() {
    let result = parse_query("from:alice)");
    assert!(result.is_err());
}

#[test]
fn test_empty_group() {
    let result = parse_query("()");
    assert!(result.is_err());
}

#[test]
fn test_dangling_or() {
    let result = parse_query("from:alice OR");
    assert!(result.is_err());
}

#[test]
fn test_operator_missing_value() {
    // "from:" at end of input with nothing after the colon
    let result = parse_query("from:");
    assert!(result.is_err());
}

#[test]
fn test_multiple_or_chains() {
    let node = parse_query("a OR b OR c").unwrap();
    match node {
        QueryNode::Or(children) => assert_eq!(children.len(), 3),
        other => panic!("Expected Or with 3 children, got {other:?}"),
    }
}

#[test]
fn test_adjacent_operators_implicit_and() {
    let node = parse_query("from:alice to:bob subject:lunch").unwrap();
    match node {
        QueryNode::And(children) => assert_eq!(children.len(), 3),
        other => panic!("Expected And with 3 children, got {other:?}"),
    }
}

#[test]
fn test_mixed_terms_and_operators() {
    let node = parse_query("invoice from:alice").unwrap();
    match node {
        QueryNode::And(children) => {
            assert_eq!(children.len(), 2);
            assert_eq!(children[0], QueryNode::Term("invoice".into()));
        }
        other => panic!("Expected And, got {other:?}"),
    }
}

#[test]
fn test_or_with_group() {
    let node = parse_query("(a b) OR (c d)").unwrap();
    match node {
        QueryNode::Or(children) => assert_eq!(children.len(), 2),
        other => panic!("Expected Or, got {other:?}"),
    }
}

#[test]
fn test_only_whitespace_query() {
    let result = parse_query("   ");
    assert!(result.is_err());
}

#[test]
fn test_unicode_in_quoted_string() {
    let node = parse_query(r#""日本語のメール""#).unwrap();
    assert_eq!(node, QueryNode::Quoted("日本語のメール".into()));
}

#[test]
fn test_rejects_query_over_length_limit() {
    let long_query = "a ".repeat(600); // ~1200 chars
    let result = parse_query(&long_query);
    assert!(result.is_err());
}

// --- Validation tests ---

#[test]
fn test_validate_rejects_blocked_label() {
    let node = parse_query("label:agent-blocked").unwrap();
    let allowed = vec!["from", "to", "subject"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("security") || err.contains("blocked") || err.contains("label"),
        "Should mention security/blocked/label: {err}"
    );
}

#[test]
fn test_validate_rejects_blocked_label_case_insensitive() {
    let node = parse_query("label:Agent-Blocked").unwrap();
    let allowed = vec!["from", "to", "subject"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_validate_rejects_negated_blocked_label() {
    let node = parse_query("-label:agent-blocked").unwrap();
    let allowed = vec!["from", "to", "subject"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_validate_rejects_disallowed_operator() {
    let node = parse_query("filename:secret.pdf").unwrap();
    let allowed = vec!["from", "to", "subject"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("filename") || err.contains("supported") || err.contains("allowed"),
        "Should mention unsupported operator: {err}"
    );
}

#[test]
fn test_validate_allows_valid_operator() {
    let node = parse_query("from:alice").unwrap();
    let allowed = vec!["from", "to", "subject"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_ok());
}

#[test]
fn test_validate_rejects_is_draft() {
    let node = parse_query("is:draft").unwrap();
    let allowed = vec!["from", "to", "subject", "is"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_validate_rejects_in_anywhere() {
    let node = parse_query("in:anywhere").unwrap();
    let allowed = vec!["from", "to", "subject", "in"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_validate_rejects_in_trash() {
    let node = parse_query("in:trash").unwrap();
    let allowed = vec!["from", "to", "subject", "in"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_validate_rejects_in_spam() {
    let node = parse_query("in:spam").unwrap();
    let allowed = vec!["from", "to", "subject", "in"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_validate_rejects_excessive_depth() {
    let deep = "(((((((((((from:alice)))))))))))";
    let node = parse_query(deep).unwrap();
    let allowed = vec!["from"];
    let result = validate_query(&node, &allowed, "agent-blocked", 5);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.to_lowercase().contains("depth") || err.to_lowercase().contains("nesting"),
        "Should mention depth: {err}"
    );
}

#[test]
fn test_validate_blocked_label_nested_in_or() {
    let node = parse_query("from:alice OR label:agent-blocked").unwrap();
    let allowed = vec!["from", "to", "subject"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_validate_blocked_label_nested_in_group() {
    let node = parse_query("(label:agent-blocked from:alice)").unwrap();
    let allowed = vec!["from", "to", "subject"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_label_operator_always_rejected() {
    let node = parse_query("label:important").unwrap();
    let allowed = vec!["from", "to", "subject"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

// --- Reconstruction tests ---

#[test]
fn test_reconstruct_simple_term() {
    let node = parse_query("hello").unwrap();
    assert_eq!(reconstruct_query(&node), "hello");
}

#[test]
fn test_reconstruct_operator() {
    let node = parse_query("from:alice").unwrap();
    assert_eq!(reconstruct_query(&node), "from:alice");
}

#[test]
fn test_reconstruct_quoted() {
    let node = parse_query(r#""hello world""#).unwrap();
    assert_eq!(reconstruct_query(&node), r#""hello world""#);
}

#[test]
fn test_reconstruct_negated() {
    let node = parse_query("-from:bob").unwrap();
    assert_eq!(reconstruct_query(&node), "-from:bob");
}

#[test]
fn test_reconstruct_or() {
    let node = parse_query("from:alice OR from:bob").unwrap();
    assert_eq!(reconstruct_query(&node), "from:alice OR from:bob");
}

#[test]
fn test_reconstruct_group() {
    let node = parse_query("(from:alice OR from:bob) subject:meeting").unwrap();
    let result = reconstruct_query(&node);
    assert!(
        result.contains("(from:alice OR from:bob)"),
        "Group should be preserved: {result}"
    );
    assert!(
        result.contains("subject:meeting"),
        "Operator should be present: {result}"
    );
}

#[test]
fn test_reconstruct_with_label_exclusion() {
    let node = parse_query("from:alice").unwrap();
    let result = reconstruct_with_label_exclusion(&node, "agent-blocked");
    assert_eq!(result, "(from:alice) -label:agent-blocked");
}

#[test]
fn test_reconstruct_complex_with_label_exclusion() {
    let node = parse_query("from:alice OR from:bob").unwrap();
    let result = reconstruct_with_label_exclusion(&node, "agent-blocked");
    assert_eq!(result, "(from:alice OR from:bob) -label:agent-blocked");
}
