//! `regex_replace(source, pattern, replacement)`.
//!
//! Same contract as Cloudflare's rules-language function of that name:
//! only the **first** match is replaced, and the replacement may reference
//! capture groups as `${1}` … `${8}`; every other `$` is literal.
//! `pattern` and `replacement` must be string literals. Both are validated
//! when the expression is parsed — an invalid regex, or a reference to a
//! group the pattern does not have, rejects the rule rather than failing
//! per request — and the regex is compiled once, there.
//!
//! Matching has byte semantics, like the `matches` operator: Unicode mode is
//! off, so `.` matches any byte and `\xff` is the byte 0xFF. The parser's
//! regex size limits apply. The `regex` crate matches in linear time, so a
//! hostile input cannot make a rule backtrack.

use std::iter;

use crate::lhs_types::Bytes;
use crate::{
    FunctionArgInvalidConstantError, FunctionArgKind, FunctionArgs, FunctionDefinition,
    FunctionDefinitionContext, FunctionParam, FunctionParamError, LhsValue, ParserSettings,
    RhsValue, Type,
};
use outer_regex::bytes::{Regex, RegexBuilder};

/// Highest capture group a replacement may reference.
const MAX_GROUP: usize = 8;

/// `regex_replace(source, pattern, replacement)`: replaces the first match of
/// `pattern` in `source`; see the module documentation for the contract.
#[derive(Debug, Default)]
pub struct RegexReplaceFunction {}

/// One piece of a parsed replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(Vec<u8>),
    Group(usize),
}

/// Parse-time state handed from `check_param` to `compile`.
#[derive(Debug, Clone, Default)]
struct Compiled {
    regex: Option<Regex>,
    replacement: Option<Vec<Segment>>,
}

fn build_regex(pattern: &[u8], settings: &ParserSettings) -> Result<Regex, String> {
    let pattern = std::str::from_utf8(pattern)
        .map_err(|_| "regex_replace pattern must be valid UTF-8".to_string())?;
    RegexBuilder::new(pattern)
        .unicode(false)
        .size_limit(settings.regex_compiled_size_limit)
        .dfa_size_limit(settings.regex_dfa_size_limit)
        .build()
        .map_err(|e| format!("invalid regex_replace pattern: {e}"))
}

/// Split `replacement` into literal bytes and `${N}` references, `N` in
/// `1..=8` and within the `groups` the pattern has.
fn parse_replacement(replacement: &[u8], groups: usize) -> Result<Vec<Segment>, String> {
    let mut segments = Vec::new();
    let mut literal = Vec::new();
    let mut rest = replacement;
    while let Some((&b, tail)) = rest.split_first() {
        if b == b'$'
            && let Some((digits, used)) = braced_digits(tail)
        {
            let n = std::str::from_utf8(digits)
                .ok()
                .and_then(|d| d.parse::<usize>().ok())
                .unwrap_or(usize::MAX);
            if !(1..=MAX_GROUP).contains(&n) || n >= groups {
                let available = (groups - 1).min(MAX_GROUP);
                return Err(if available == 0 {
                    format!(
                        "regex_replace replacement references ${{{n}}}, but the pattern has \
                         no capture groups"
                    )
                } else {
                    format!(
                        "regex_replace replacement references ${{{n}}}; only \
                         ${{1}}..${{{available}}} exist"
                    )
                });
            }
            if !literal.is_empty() {
                segments.push(Segment::Literal(std::mem::take(&mut literal)));
            }
            segments.push(Segment::Group(n));
            rest = &tail[used..];
            continue;
        }
        literal.push(b);
        rest = tail;
    }
    if !literal.is_empty() {
        segments.push(Segment::Literal(literal));
    }
    Ok(segments)
}

/// `{digits}` at the start of `s` (the text after a `$`): the digits and how
/// many bytes the reference spans.
fn braced_digits(s: &[u8]) -> Option<(&[u8], usize)> {
    let body = s.strip_prefix(b"{")?;
    let close = body.iter().position(|&c| c == b'}')?;
    let digits = &body[..close];
    (!digits.is_empty() && digits.iter().all(u8::is_ascii_digit)).then_some((digits, close + 2))
}

/// Replace the first match of `regex` in `source`.
fn replace_first(regex: &Regex, replacement: &[Segment], source: &[u8]) -> Vec<u8> {
    let Some(caps) = regex.captures(source) else {
        return source.to_vec();
    };
    let whole = caps.get(0).expect("group 0 is the match");
    let mut out = Vec::with_capacity(source.len());
    out.extend_from_slice(&source[..whole.start()]);
    for segment in replacement {
        match segment {
            Segment::Literal(bytes) => out.extend_from_slice(bytes),
            Segment::Group(n) => {
                if let Some(group) = caps.get(*n) {
                    out.extend_from_slice(group.as_bytes());
                }
            }
        }
    }
    out.extend_from_slice(&source[whole.end()..]);
    out
}

fn literal<'a>(param: &FunctionParam<'a>) -> Option<&'a [u8]> {
    match param.as_constant() {
        Ok(RhsValue::Bytes(bytes)) => Some(bytes.as_ref()),
        _ => None,
    }
}

fn state(ctx: Option<&mut FunctionDefinitionContext>) -> Option<&mut Compiled> {
    ctx.and_then(|c| c.downcast_mut::<Compiled>())
}

impl FunctionDefinition for RegexReplaceFunction {
    fn context(&self) -> Option<FunctionDefinitionContext> {
        Some(FunctionDefinitionContext::new(Compiled::default()))
    }

    fn check_param(
        &self,
        settings: &ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        next_param: &FunctionParam<'_>,
        ctx: Option<&mut FunctionDefinitionContext>,
    ) -> Result<(), FunctionParamError> {
        match params.len() {
            0 => {
                next_param.arg_kind().expect(FunctionArgKind::Field)?;
                next_param.expect_val_type(iter::once(Type::Bytes.into()))?;
            }
            1 => {
                next_param.arg_kind().expect(FunctionArgKind::Literal)?;
                next_param.expect_val_type(iter::once(Type::Bytes.into()))?;
                let regex = build_regex(literal(next_param).unwrap_or_default(), settings)
                    .map_err(FunctionArgInvalidConstantError::new)?;
                if let Some(state) = state(ctx) {
                    state.regex = Some(regex);
                }
            }
            2 => {
                next_param.arg_kind().expect(FunctionArgKind::Literal)?;
                next_param.expect_val_type(iter::once(Type::Bytes.into()))?;
                let state = state(ctx).expect("regex_replace context is always provided");
                let groups = state
                    .regex
                    .as_ref()
                    .expect("pattern is checked before the replacement")
                    .captures_len();
                let replacement =
                    parse_replacement(literal(next_param).unwrap_or_default(), groups)
                        .map_err(FunctionArgInvalidConstantError::new)?;
                state.replacement = Some(replacement);
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn return_type(
        &self,
        _: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<&FunctionDefinitionContext>,
    ) -> Type {
        Type::Bytes
    }

    fn arg_count(&self) -> (usize, Option<usize>) {
        (3, Some(0))
    }

    fn compile(
        &self,
        _: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        ctx: Option<FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        // `check_param` validated and built both; parsing cannot succeed
        // without them.
        let state = ctx
            .and_then(|c| c.downcast::<Compiled>().ok())
            .expect("regex_replace context is always provided");
        let regex = state.regex.expect("pattern checked at parse time");
        let replacement = state
            .replacement
            .expect("replacement checked at parse time");
        Box::new(move |args| match args.next()? {
            Ok(LhsValue::Bytes(source)) => Some(LhsValue::Bytes(Bytes::Owned(
                replace_first(&regex, &replacement, source.as_ref()).into_boxed_slice(),
            ))),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecutionContext, Scheme, SchemeBuilder};

    fn scheme() -> Scheme {
        let mut builder = SchemeBuilder::new();
        builder.add_field("src", Type::Bytes).unwrap();
        builder
            .add_function("regex_replace", RegexReplaceFunction::default())
            .unwrap();
        builder.build()
    }

    /// Evaluate `regex_replace(src, pattern, replacement)` on `input`.
    fn eval(pattern: &str, replacement: &str, input: &str) -> Option<String> {
        eval_bytes(pattern, replacement, input.as_bytes())
    }

    fn eval_bytes(pattern: &str, replacement: &str, input: &[u8]) -> Option<String> {
        let scheme = scheme();
        let expr = format!("regex_replace(src, {pattern:?}, {replacement:?})");
        let value = scheme.parse_value(&expr).unwrap().compile();
        let mut ctx = ExecutionContext::new(&scheme);
        ctx.set_field_value(scheme.get_field("src").unwrap(), Bytes::from(input))
            .unwrap();
        // Inner `Err` = the expression produced no value.
        match value.execute(&ctx).unwrap() {
            Ok(LhsValue::Bytes(b)) => Some(String::from_utf8_lossy(&b).into_owned()),
            Ok(other) => panic!("unexpected {other:?}"),
            Err(_) => None,
        }
    }

    #[test]
    fn replaces_first_match_only() {
        assert_eq!(eval("o", "0", "foo boo").as_deref(), Some("f0o boo"));
    }

    #[test]
    fn capture_groups() {
        assert_eq!(
            eval("^http://(.*)$", "https://${1}", "http://example.com/a").as_deref(),
            Some("https://example.com/a")
        );
    }

    #[test]
    fn no_match_returns_source() {
        assert_eq!(
            eval("^http://", "https://", "https://already").as_deref(),
            Some("https://already")
        );
    }

    #[test]
    fn invalid_pattern_is_a_parse_error() {
        let scheme = scheme();
        let err = scheme
            .parse_value(r#"regex_replace(src, "(unclosed", "x")"#)
            .unwrap_err();
        assert!(err.to_string().contains("invalid"), "{err}");
    }

    #[test]
    fn pattern_and_replacement_must_be_literals() {
        let scheme = scheme();
        assert!(
            scheme
                .parse_value(r#"regex_replace(src, src, "x")"#)
                .is_err()
        );
        assert!(
            scheme
                .parse_value(r#"regex_replace(src, "a", src)"#)
                .is_err()
        );
    }

    #[test]
    fn oversized_pattern_is_rejected() {
        let scheme = scheme();
        let huge = r#"regex_replace(src, "(a{1000}){1000}", "x")"#;
        assert!(scheme.parse_value(huge).is_err());
    }

    /// Only `${1}` … `${8}` are references; any other `$` is literal.
    #[test]
    fn dollar_is_literal_outside_a_reference() {
        assert_eq!(eval("0", "$5 off", "0").as_deref(), Some("$5 off"));
        assert_eq!(eval("x", "a$b", "x").as_deref(), Some("a$b"));
        assert_eq!(eval("x", "$$", "x").as_deref(), Some("$$"));
        assert_eq!(eval("(?P<n>a)", "$n", "a").as_deref(), Some("$n"));
        assert_eq!(eval("(?P<n>a)", "${n}", "a").as_deref(), Some("${n}"));
    }

    /// A reference to a group the pattern does not have, or beyond `${8}`,
    /// is a parse error rather than a silent empty string.
    #[test]
    fn out_of_range_reference_is_a_parse_error() {
        let scheme = scheme();
        for expr in [
            r#"regex_replace(src, "(a)", "${2}")"#,
            r#"regex_replace(src, "(a)(b)(c)(d)(e)(f)(g)(h)(i)", "${9}")"#,
            r#"regex_replace(src, "a", "${0}")"#,
        ] {
            assert!(scheme.parse_value(expr).is_err(), "{expr}");
        }
        assert!(
            scheme
                .parse_value(r#"regex_replace(src, "(a)(b)(c)(d)(e)(f)(g)(h)", "${8}")"#)
                .is_ok()
        );
    }

    /// Byte semantics, like the `matches` operator: `.` matches any byte,
    /// including ones that are not valid UTF-8.
    #[test]
    fn matches_bytes_not_codepoints() {
        assert_eq!(eval_bytes("^.a$", "X", b"\xffa").as_deref(), Some("X"));
        assert_eq!(eval_bytes("\\xff", "Y", b"\xff").as_deref(), Some("Y"));
    }

    /// The parser's regex limits apply, as they do to `matches`.
    #[test]
    fn honours_parser_regex_limits() {
        let scheme = scheme();
        let tight = crate::ParserSettings {
            regex_compiled_size_limit: 1024,
            ..Default::default()
        };
        let expr = r#"regex_replace(src, "a{200}", "x")"#;
        assert!(scheme.parse_value(expr).is_ok());
        assert!(
            crate::FilterParser::with_settings(&scheme, tight)
                .parse_value(expr)
                .is_err()
        );
    }
}
