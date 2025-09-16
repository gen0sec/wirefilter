use std::borrow::Cow;

use crate::{LhsValue, Type};

use super::{FunctionArgKind, FunctionArgs, FunctionDefinition};

/// Returns a substring (slice by byte index) of a String/Bytes field.
///
/// Usage:
///
/// substring(field, start, end?)
///
/// - `field` must be a non-literal field whose value is `String`/`Bytes` (for
///   example `http.request.body.raw`).
/// - `start` is an `Integer` byte index indicating the first byte to include.
/// - `end` is an optional `Integer` byte index indicating the first byte to
///   exclude. If omitted, the substring runs to the end of the field.
///
/// Index semantics:
/// - Indexing is by byte, not Unicode scalar; the first byte is index 0.
/// - Negative indexes count from the end of the value: an index of `-1` refers
///   to the last byte, `-2` to the penultimate byte, and so on.
/// - Out-of-range indexes are clamped to the bounds `[0, len]` where `len` is
///   the byte length of the field. If `end < start` after clamping, an empty
///   string is returned.
///
/// Examples:
///
/// If `http.request.body.raw` is `"asdfghjk"`:
///
/// substring(http.request.body.raw, 2, 5)   -> "dfg"
/// substring(http.request.body.raw, 2)      -> "dfghjk"
/// substring(http.request.body.raw, -2)     -> "jk"
/// substring(http.request.body.raw, 0, -2)  -> "asdfgh"
#[derive(Debug, Default)]
pub struct SubstringFunction {}

#[inline]
fn substring_impl<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let source_arg = args.next().expect("expected at least 2 arguments, got 0");
    let start_arg = args.next().expect("expected at least 2 arguments, got 1");
    let end_arg = args.next();

    if args.next().is_some() {
        panic!("expected maximum 3 arguments, got {}", 4 + args.count());
    }

    match (source_arg, start_arg, end_arg) {
        (Ok(LhsValue::Bytes(source)), Ok(LhsValue::Int(start)), Some(Ok(LhsValue::Int(end)))) => {
            let s = source.as_ref();
            let len = s.len() as i64;

            let mut start_idx = if start < 0 { len + start } else { start };
            let mut end_idx = if end < 0 { len + end } else { end };

            if start_idx < 0 {
                start_idx = 0
            }
            if end_idx < 0 {
                end_idx = 0
            }
            if start_idx > len {
                start_idx = len
            }
            if end_idx > len {
                end_idx = len
            }

            if end_idx < start_idx {
                return Some(LhsValue::Bytes(Cow::Owned(Vec::new())));
            }

            let start_us = start_idx as usize;
            let end_us = end_idx as usize;
            Some(LhsValue::Bytes(Cow::Owned(s[start_us..end_us].to_vec())))
        }
        (Ok(LhsValue::Bytes(source)), Ok(LhsValue::Int(start)), None) => {
            let s = source.as_ref();
            let len = s.len() as i64;
            let mut start_idx = if start < 0 { len + start } else { start };
            if start_idx < 0 {
                start_idx = 0
            }
            if start_idx > len {
                start_idx = len
            }

            let start_us = start_idx as usize;
            Some(LhsValue::Bytes(Cow::Owned(s[start_us..].to_vec())))
        }
        (Err(Type::Bytes), _, _) => None,
        (_, Err(Type::Int), _) => None,
        _ => unreachable!(),
    }
}

impl FunctionDefinition for SubstringFunction {
    fn check_param(
        &self,
        _: &crate::ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = super::FunctionParam<'_>>,
        next_param: &super::FunctionParam<'_>,
        _: Option<&mut super::FunctionDefinitionContext>,
    ) -> Result<(), super::FunctionParamError> {
        match params.len() {
            0 => {
                next_param.expect_arg_kind(FunctionArgKind::Field)?;
                next_param.expect_val_type(std::iter::once(Type::Bytes.into()))?;
            }
            1 => {
                next_param.expect_arg_kind(FunctionArgKind::Literal)?;
                next_param.expect_val_type(std::iter::once(Type::Int.into()))?;
            }
            2 => {
                next_param.expect_arg_kind(FunctionArgKind::Literal)?;
                next_param.expect_val_type(std::iter::once(Type::Int.into()))?;
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
        (2, Some(1))
    }

    fn compile(
        &self,
        _: &mut dyn ExactSizeIterator<Item = super::FunctionParam<'_>>,
        _: Option<super::FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        Box::new(substring_impl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    fn owned(s: &str) -> LhsValue<'_> {
        LhsValue::Bytes(Cow::Owned(s.as_bytes().to_vec()))
    }

    #[test]
    fn test_substring_examples() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"asdfghjk"))),
            Ok(LhsValue::Int(2)),
            Ok(LhsValue::Int(5)),
        ]
        .into_iter();
        assert_eq!(substring_impl(&mut args), Some(owned("dfg")));

        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"asdfghjk"))),
            Ok(LhsValue::Int(2)),
        ]
        .into_iter();
        assert_eq!(substring_impl(&mut args), Some(owned("dfghjk")));

        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"asdfghjk"))),
            Ok(LhsValue::Int(-2)),
        ]
        .into_iter();
        assert_eq!(substring_impl(&mut args), Some(owned("jk")));

        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"asdfghjk"))),
            Ok(LhsValue::Int(0)),
            Ok(LhsValue::Int(-2)),
        ]
        .into_iter();
        assert_eq!(substring_impl(&mut args), Some(owned("asdfgh")));
    }

    #[test]
    fn test_substring_out_of_bounds() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"abc"))),
            Ok(LhsValue::Int(10)),
        ]
        .into_iter();
        assert_eq!(substring_impl(&mut args), Some(owned("")));

        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"abc"))),
            Ok(LhsValue::Int(-10)),
        ]
        .into_iter();
        assert_eq!(substring_impl(&mut args), Some(owned("abc")));
    }

    #[test]
    #[should_panic(expected = "expected at least 2 arguments, got 0")]
    fn test_panic_no_args() {
        let mut args = vec![].into_iter();
        substring_impl(&mut args);
    }
}
