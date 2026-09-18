//! `regex_replace(source, pattern, replacement)`.
//!
//! Same contract as Cloudflare's rules-language function of that name:
//! only the **first** match is replaced, and the replacement may reference
//! capture groups as `${1}` … `${8}`. `pattern` and `replacement` must be
//! string literals; the pattern is validated when the expression is parsed —
//! a bad regex rejects the rule rather than failing per request — and
//! compiled once when it is compiled.
//!
//! The `regex` crate matches in linear time, so a hostile input cannot make
//! a rule backtrack; the compiled size is capped as well.

use std::iter;

use crate::lhs_types::Bytes;
use crate::{
    FunctionArgInvalidConstantError, FunctionArgKind, FunctionArgs, FunctionDefinition,
    FunctionDefinitionContext, FunctionParam, FunctionParamError, LhsValue, ParserSettings,
    RhsValue, Type,
};
use outer_regex::bytes::Regex;

/// Upper bound on a compiled pattern, well above anything a header rewrite
/// needs.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

#[derive(Debug, Default)]
pub struct RegexReplaceFunction {}

fn compile(pattern: &[u8]) -> Result<Regex, String> {
    let pattern = std::str::from_utf8(pattern)
        .map_err(|_| "regex_replace pattern must be valid UTF-8".to_string())?;
    outer_regex::bytes::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| format!("invalid regex_replace pattern: {e}"))
}

fn literal<'a>(param: &FunctionParam<'a>) -> Option<&'a [u8]> {
    match param.as_constant() {
        Ok(RhsValue::Bytes(bytes)) => Some(bytes.as_ref()),
        _ => None,
    }
}

impl FunctionDefinition for RegexReplaceFunction {
    fn check_param(
        &self,
        _: &ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        next_param: &FunctionParam<'_>,
        _: Option<&mut FunctionDefinitionContext>,
    ) -> Result<(), FunctionParamError> {
        match params.len() {
            0 => {
                next_param.arg_kind().expect(FunctionArgKind::Field)?;
                next_param.expect_val_type(iter::once(Type::Bytes.into()))?;
            }
            1 => {
                next_param.arg_kind().expect(FunctionArgKind::Literal)?;
                next_param.expect_val_type(iter::once(Type::Bytes.into()))?;
                let pattern = literal(next_param).unwrap_or_default();
                compile(pattern).map_err(FunctionArgInvalidConstantError::new)?;
            }
            2 => {
                next_param.arg_kind().expect(FunctionArgKind::Literal)?;
                next_param.expect_val_type(iter::once(Type::Bytes.into()))?;
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
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        // `check_param` already required both literals and a pattern that
        // compiles, so these cannot fail here.
        let _source = params.next();
        let pattern = params.next().as_ref().and_then(literal).map(<[u8]>::to_vec);
        let replacement = params.next().as_ref().and_then(literal).map(<[u8]>::to_vec);
        let (Some(pattern), Some(replacement)) = (pattern, replacement) else {
            return Box::new(|_| None);
        };
        let Ok(regex) = compile(&pattern) else {
            return Box::new(|_| None);
        };
        Box::new(move |args| {
            // The pattern and replacement are baked in; only the source is
            // read at execution time.
            match args.next()? {
                Ok(LhsValue::Bytes(source)) => {
                    let replaced = regex.replace(source.as_ref(), replacement.as_slice());
                    Some(LhsValue::Bytes(Bytes::Owned(
                        replaced.into_owned().into_boxed_slice(),
                    )))
                }
                _ => None,
            }
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
        let scheme = scheme();
        let expr = format!("regex_replace(src, {pattern:?}, {replacement:?})");
        let value = scheme.parse_value(&expr).unwrap().compile();
        let mut ctx = ExecutionContext::new(&scheme);
        ctx.set_field_value(scheme.get_field("src").unwrap(), input)
            .unwrap();
        // Inner `Err` = the expression produced no value.
        match value.execute(&ctx).unwrap() {
            Ok(LhsValue::Bytes(b)) => Some(String::from_utf8(b.to_vec()).unwrap()),
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
}
