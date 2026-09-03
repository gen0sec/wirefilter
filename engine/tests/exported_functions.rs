//! Every function the engine exports must be registrable and executable.
//!
//! Regression cover for a real defect: five function implementations lived in
//! `functions/` with passing unit tests, but their modules were never declared
//! in `functions/mod.rs`. They were uncompiled, unexported and unregistrable,
//! and no unit test could notice -- the tests were inside the very files that
//! were not being built. Only a test that goes through the public surface
//! (`SchemeBuilder::add_function` -> parse -> execute) catches this class.

use wirefilter::{
    ConcatFunction, EndsWithFunction, ExecutionContext, JsonLookupIntegerFunction,
    JsonLookupStringFunction, LowerFunction, RemoveQueryArgsFunction, SchemeBuilder,
    StartsWithFunction, ToStringFunction, Type, UpperFunction,
};

/// Registers every publicly exported function under its Cloudflare-compatible
/// name. A name that fails to register fails the build of every rule using it.
fn scheme_with_all_functions() -> wirefilter::Scheme {
    let mut b = SchemeBuilder::new();
    b.add_field("body", Type::Bytes).unwrap();
    b.add_field("query", Type::Bytes).unwrap();
    b.add_field("n", Type::Int).unwrap();
    b.add_function("lookup_json_string", JsonLookupStringFunction::default())
        .unwrap();
    b.add_function("lookup_json_integer", JsonLookupIntegerFunction::default())
        .unwrap();
    b.add_function("remove_query_args", RemoveQueryArgsFunction::default())
        .unwrap();
    b.add_function("to_string", ToStringFunction::default()).unwrap();
    b.add_function("upper", UpperFunction::default()).unwrap();
    b.add_function("lower", LowerFunction::default()).unwrap();
    b.add_function("concat", ConcatFunction::default()).unwrap();
    b.add_function("starts_with", StartsWithFunction::default()).unwrap();
    b.add_function("ends_with", EndsWithFunction::default()).unwrap();
    b.build()
}

fn eval(expr: &str, body: &str) -> bool {
    let scheme = scheme_with_all_functions();
    let filter = scheme
        .parse(expr)
        .unwrap_or_else(|e| panic!("{expr} must parse: {e}"))
        .compile();
    let mut ctx = ExecutionContext::new(&scheme);
    ctx.set_field_value(scheme.get_field("body").unwrap(), body).unwrap();
    ctx.set_field_value(scheme.get_field("query").unwrap(), "a=1&b=2").unwrap();
    ctx.set_field_value(scheme.get_field("n").unwrap(), 7i64).unwrap();
    filter.execute(&ctx).unwrap()
}

#[test]
fn every_exported_function_registers() {
    // The assertion is that building the scheme does not panic: each
    // add_function above would fail on an unexported or duplicate name.
    let scheme = scheme_with_all_functions();
    assert!(scheme.get_field("body").is_ok());
}

#[test]
fn json_lookup_string_reads_a_key() {
    assert!(eval(
        r#"lookup_json_string(body, "operationName") == "currentUser""#,
        r#"{"operationName":"currentUser"}"#,
    ));
}

#[test]
fn json_lookup_string_supports_an_allow_list() {
    let expr = r#"lookup_json_string(body, "operationName") in {"currentUser" "publicApps"}"#;
    assert!(eval(expr, r#"{"operationName":"currentUser"}"#));
    assert!(!eval(expr, r#"{"operationName":"deleteEverything"}"#));
}

#[test]
fn json_lookup_string_on_malformed_json_does_not_match() {
    // Matters for a positive model: the allow-list membership test is false,
    // so `not (... in {...})` blocks. Unparseable input must never satisfy an
    // allow-list by accident.
    assert!(!eval(
        r#"lookup_json_string(body, "operationName") in {"currentUser"}"#,
        "not json at all",
    ));
    assert!(!eval(
        r#"lookup_json_string(body, "operationName") in {"currentUser"}"#,
        r#"{"query":"{ me }"}"#,
    ));
}

#[test]
fn json_lookup_string_traverses_nested_keys() {
    assert!(eval(
        r#"lookup_json_string(body, "a", "b") == "deep""#,
        r#"{"a":{"b":"deep"}}"#,
    ));
}

#[test]
fn json_lookup_integer_reads_a_number() {
    assert!(eval(r#"lookup_json_integer(body, "n") == 42"#, r#"{"n":42}"#));
}

#[test]
fn remove_query_args_drops_the_named_arg() {
    assert!(eval(r#"remove_query_args(query, "a") == "b=2""#, "{}"));
}

#[test]
fn upper_and_lower_and_to_string_round_trip() {
    assert!(eval(r#"upper(lookup_json_string(body, "k")) == "ABC""#, r#"{"k":"abc"}"#));
    assert!(eval(r#"lower(lookup_json_string(body, "k")) == "abc""#, r#"{"k":"ABC"}"#));
    assert!(eval(r#"to_string(n) == "7""#, "{}"));
}
