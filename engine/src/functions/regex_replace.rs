use crate::lhs_types::Bytes;
use crate::{FunctionArgs, FunctionDefinition, LhsValue, Type};
use outer_regex::bytes::Regex;
use std::iter;

/// Replaces the first occurrence of a regular expression match in `source` with
/// `replacement`. The replacement string can reference capture groups using
/// `${1}`..`${8}` and escape a literal `$` using `$$`.
#[derive(Debug, Default)]
pub struct RegexReplaceFunction {}

fn build_replacement(
    replacement_str: &str,
    caps: &outer_regex::bytes::Captures<'_>,
    src: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(replacement_str.len());
    let bytes = replacement_str.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'$' {
                out.push(b'$');
                i += 2;
                continue;
            }
            if i + 2 < bytes.len()
                && bytes[i + 1] == b'{'
                && let Some(close_pos) = bytes[i + 2..].iter().position(|&b| b == b'}')
            {
                let num_slice = &bytes[i + 2..i + 2 + close_pos];
                if let Ok(num_str) = std::str::from_utf8(num_slice)
                    && let Ok(n) = num_str.parse::<usize>()
                    && n > 0
                    && n <= 8
                {
                    if let Some(m) = caps.get(n) {
                        out.extend_from_slice(&src[m.start()..m.end()]);
                    }
                    i += 2 + close_pos + 1;
                    continue;
                }
                out.push(b'$');
                i += 1;
                continue;
            }
            out.push(b'$');
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

#[inline]
fn regex_replace_impl<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let source_arg = args.next().expect("expected 3 arguments, got 0");
    let pattern_arg = args.next().expect("expected 3 arguments, got 1");
    let replacement_arg = args.next().expect("expected 3 arguments, got 2");

    if args.next().is_some() {
        panic!("expected 3 arguments, got {}", 4 + args.count());
    }

    match (source_arg, pattern_arg, replacement_arg) {
        (
            Ok(LhsValue::Bytes(source)),
            Ok(LhsValue::Bytes(pattern_bytes)),
            Ok(LhsValue::Bytes(replacement_bytes)),
        ) => {
            let pattern_str =
                std::str::from_utf8(pattern_bytes.as_ref()).expect("Pattern must be valid UTF-8");
            let replacement_str = std::str::from_utf8(replacement_bytes.as_ref())
                .expect("Replacement must be valid UTF-8");

            let re = Regex::new(pattern_str).expect("Invalid regex pattern");

            let src = source.as_ref();
            if let Some(caps) = re.captures(src) {
                let m = caps.get(0).unwrap();
                let mut out = Vec::with_capacity(src.len());
                out.extend_from_slice(&src[..m.start()]);
                let repl = build_replacement(replacement_str, &caps, src);
                out.extend_from_slice(&repl);
                out.extend_from_slice(&src[m.end()..]);
                Some(LhsValue::Bytes(Bytes::Owned(out.into_boxed_slice())))
            } else {
                Some(LhsValue::Bytes(Bytes::Owned(
                    src.to_vec().into_boxed_slice(),
                )))
            }
        }
        (Err(Type::Bytes), _, _) => None,
        (_, Err(Type::Bytes), _) => None,
        (_, _, Err(Type::Bytes)) => None,
        _ => unreachable!(),
    }
}

impl FunctionDefinition for RegexReplaceFunction {
    fn check_param(
        &self,
        _: &crate::ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = super::FunctionParam<'_>>,
        next_param: &super::FunctionParam<'_>,
        _: Option<&mut super::FunctionDefinitionContext>,
    ) -> Result<(), super::FunctionParamError> {
        match params.len() {
            0 => {
                next_param
                    .arg_kind()
                    .expect(super::FunctionArgKind::Field)?;
                next_param.expect_val_type(iter::once(Type::Bytes.into()))?;
            }
            1 => {
                next_param
                    .arg_kind()
                    .expect(super::FunctionArgKind::Literal)?;
                next_param.expect_val_type(iter::once(Type::Bytes.into()))?;
            }
            2 => {
                next_param
                    .arg_kind()
                    .expect(super::FunctionArgKind::Literal)?;
                next_param.expect_val_type(iter::once(Type::Bytes.into()))?;
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    fn return_type(
        &self,
        _: &mut dyn ExactSizeIterator<Item = super::FunctionParam<'_>>,
        _: Option<&super::FunctionDefinitionContext>,
    ) -> crate::Type {
        Type::Bytes
    }

    fn arg_count(&self) -> (usize, Option<usize>) {
        (3, Some(0))
    }

    fn compile(
        &self,
        _: &mut dyn ExactSizeIterator<Item = super::FunctionParam<'_>>,
        _: Option<super::FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        Box::new(regex_replace_impl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned_bytes(s: &str) -> LhsValue<'_> {
        LhsValue::Bytes(Bytes::Owned(s.as_bytes().to_vec().into_boxed_slice()))
    }

    #[test]
    fn test_regex_replace_literal() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/foo/bar"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/bar$"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/baz"))),
        ]
        .into_iter();
        assert_eq!(regex_replace_impl(&mut args), Some(owned_bytes("/foo/baz")));
    }

    #[test]
    fn test_regex_replace_no_match() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/x"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"^/y$"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/mumble"))),
        ]
        .into_iter();
        assert_eq!(regex_replace_impl(&mut args), Some(owned_bytes("/x")));
    }

    #[test]
    fn test_regex_replace_case_sensitive() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/foo"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"^/FOO$"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/x"))),
        ]
        .into_iter();
        assert_eq!(regex_replace_impl(&mut args), Some(owned_bytes("/foo")));
    }

    #[test]
    fn test_regex_replace_first_only() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/a/a"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/a"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/b"))),
        ]
        .into_iter();
        assert_eq!(regex_replace_impl(&mut args), Some(owned_bytes("/b/a")));
    }

    #[test]
    fn test_regex_replace_escape_dollar() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/b"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"^/b$"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/b$$"))),
        ]
        .into_iter();
        assert_eq!(regex_replace_impl(&mut args), Some(owned_bytes("/b$")));
    }

    #[test]
    fn test_regex_replace_capture_groups() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/foo/a/path"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"^/foo/([^/]*)/(.*)$"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/bar/${2}/${1}"))),
        ]
        .into_iter();
        assert_eq!(
            regex_replace_impl(&mut args),
            Some(owned_bytes("/bar/path/a"))
        );
    }

    #[test]
    fn test_regex_replace_empty_replacement_deletes_match() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/foo/bar/baz"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"/bar"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b""))),
        ]
        .into_iter();
        assert_eq!(regex_replace_impl(&mut args), Some(owned_bytes("/foo/baz")));
    }

    #[test]
    fn test_regex_replace_preserves_prefix_and_suffix() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"abXXcd"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"X+"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"-"))),
        ]
        .into_iter();
        assert_eq!(regex_replace_impl(&mut args), Some(owned_bytes("ab-cd")));
    }

    #[test]
    fn test_regex_replace_dollar_without_braces_is_literal() {
        // Only `${n}` is a capture reference; a bare `$1` is copied verbatim.
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"foo"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"(foo)"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"$1"))),
        ]
        .into_iter();
        assert_eq!(regex_replace_impl(&mut args), Some(owned_bytes("$1")));
    }

    #[test]
    fn test_regex_replace_group_out_of_range_is_literal() {
        // `${9}` exceeds the supported `${1}`..`${8}` range, so it stays literal.
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"foo"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"(foo)"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"${9}"))),
        ]
        .into_iter();
        assert_eq!(regex_replace_impl(&mut args), Some(owned_bytes("${9}")));
    }

    #[test]
    fn test_regex_replace_trailing_dollar_is_literal() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"foo"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"(foo)"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"${1}$"))),
        ]
        .into_iter();
        assert_eq!(regex_replace_impl(&mut args), Some(owned_bytes("foo$")));
    }

    #[test]
    fn test_regex_replace_multiple_groups_subset_referenced() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"a=1;b=2"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(
                b"^(\\w)=(\\d);(\\w)=(\\d)$",
            ))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"${3}${1}"))),
        ]
        .into_iter();
        assert_eq!(regex_replace_impl(&mut args), Some(owned_bytes("ba")));
    }

    #[test]
    fn test_regex_replace_non_utf8_source_preserved() {
        // The source need not be valid UTF-8; bytes outside the match are kept intact.
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"\xff\xfeXX\xfd"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"X+"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"_"))),
        ]
        .into_iter();
        assert_eq!(
            regex_replace_impl(&mut args),
            Some(LhsValue::Bytes(Bytes::Owned(
                b"\xff\xfe_\xfd".to_vec().into_boxed_slice()
            )))
        );
    }

    #[test]
    fn test_regex_replace_source_type_error_returns_none() {
        let mut args = vec![
            Err(Type::Bytes),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"x"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"y"))),
        ]
        .into_iter();
        assert_eq!(regex_replace_impl(&mut args), None);
    }

    #[test]
    fn test_regex_replace_pattern_type_error_returns_none() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"x"))),
            Err(Type::Bytes),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"y"))),
        ]
        .into_iter();
        assert_eq!(regex_replace_impl(&mut args), None);
    }

    #[test]
    fn test_regex_replace_replacement_type_error_returns_none() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"x"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"x"))),
            Err(Type::Bytes),
        ]
        .into_iter();
        assert_eq!(regex_replace_impl(&mut args), None);
    }

    #[test]
    #[should_panic(expected = "expected 3 arguments, got 4")]
    fn test_panic_too_many_args() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"x"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"x"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"y"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"z"))),
        ]
        .into_iter();
        regex_replace_impl(&mut args);
    }

    #[test]
    #[should_panic(expected = "expected 3 arguments, got 0")]
    fn test_panic_no_args() {
        let mut args = vec![].into_iter();
        regex_replace_impl(&mut args);
    }
}
