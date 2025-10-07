use std::borrow::Cow;
use std::collections::HashSet;

use crate::{LhsValue, Type};

use super::{FunctionArgKind, FunctionArgs, FunctionDefinition};

/// Removes one or more query string parameters from a URI query string.
///
/// The first argument must be a field (for example `http.request.uri.query`),
/// and the remaining arguments must be literal byte strings naming the
/// parameters to remove. The function removes all occurrences of the named
/// parameters and preserves the order of unaffected parameters. If the result
/// is empty, an empty string is returned.
#[derive(Debug, Default)]
pub struct RemoveQueryArgsFunction {}

#[inline]
fn remove_query_args_impl<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let source_arg = args.next().expect("expected at least 2 args, got 0");
    let first_param = args.next().expect("expected at least 2 args, got 1");

    let mut param_args = vec![first_param];
    for arg in args {
        param_args.push(arg);
    }

    match (source_arg, param_args.as_slice()) {
        (Ok(LhsValue::Bytes(source)), params) => {
            let mut to_remove = HashSet::new();
            for p in params.iter() {
                match p {
                    Ok(LhsValue::Bytes(b)) => {
                        to_remove.insert(b.as_ref().to_vec());
                    }
                    Err(Type::Bytes) => return None,
                    _ => unreachable!(),
                }
            }

            let src = source.as_ref();
            let mut out: Vec<u8> = Vec::with_capacity(src.len());

            let mut first = true;
            for seg in src.split(|b| *b == b'&') {
                let key = match seg.iter().position(|b| *b == b'=') {
                    Some(pos) => &seg[..pos],
                    None => seg,
                };

                if to_remove.contains(key) {
                    continue;
                }

                if !first {
                    out.push(b'&');
                }
                first = false;
                out.extend_from_slice(seg);
            }

            Some(LhsValue::Bytes(Cow::Owned(out)))
        }
        (Err(Type::Bytes), _) => None,
        _ => unreachable!(),
    }
}

impl FunctionDefinition for RemoveQueryArgsFunction {
    fn check_param(
        &self,
        _: &crate::ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = super::FunctionParam<'_>>,
        next_param: &super::FunctionParam<'_>,
        _: Option<&mut super::FunctionDefinitionContext>,
    ) -> Result<(), super::FunctionParamError> {
        match params.len() {
            0 => {
                next_param.arg_kind().expect(FunctionArgKind::Field)?;
                next_param.expect_val_type(std::iter::once(Type::Bytes.into()))?;
            }
            _ => {
                next_param.arg_kind().expect(FunctionArgKind::Literal)?;
                next_param.expect_val_type(std::iter::once(Type::Bytes.into()))?;
            }
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
        (2, None)
    }

    fn compile(
        &self,
        _: &mut dyn ExactSizeIterator<Item = super::FunctionParam<'_>>,
        _: Option<super::FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        Box::new(remove_query_args_impl)
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
    fn test_remove_query_args_basic() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"order=asc&country=GB"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"country"))),
        ]
        .into_iter();
        assert_eq!(remove_query_args_impl(&mut args), Some(owned("order=asc")));

        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"order=asc&country=GB"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"order"))),
        ]
        .into_iter();
        assert_eq!(remove_query_args_impl(&mut args), Some(owned("country=GB")));

        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"order=asc&country=GB"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"search"))),
        ]
        .into_iter();
        assert_eq!(
            remove_query_args_impl(&mut args),
            Some(owned("order=asc&country=GB"))
        );
    }

    #[test]
    fn test_remove_query_args_repeated() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(
                b"category=Foo&order=desc&category=Bar",
            ))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"order"))),
        ]
        .into_iter();
        assert_eq!(
            remove_query_args_impl(&mut args),
            Some(owned("category=Foo&category=Bar"))
        );

        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(
                b"category=Foo&order=desc&category=Bar",
            ))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"category"))),
        ]
        .into_iter();
        assert_eq!(remove_query_args_impl(&mut args), Some(owned("order=desc")));
    }

    #[test]
    fn test_remove_query_args_multiple_params() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"a=1&b=2&c=3&d=4"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"b"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"d"))),
        ]
        .into_iter();
        assert_eq!(remove_query_args_impl(&mut args), Some(owned("a=1&c=3")));
    }

    #[test]
    fn test_remove_query_args_no_match() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"x=1&y=2"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"z"))),
        ]
        .into_iter();
        assert_eq!(remove_query_args_impl(&mut args), Some(owned("x=1&y=2")));
    }

    #[test]
    fn test_remove_query_args_empty_result() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"only=one"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"only"))),
        ]
        .into_iter();
        assert_eq!(remove_query_args_impl(&mut args), Some(owned("")));
    }

    #[test]
    #[should_panic(expected = "expected at least 2 args, got 0")]
    fn test_panic_no_args() {
        let mut args = vec![].into_iter();
        remove_query_args_impl(&mut args);
    }

    #[test]
    #[should_panic(expected = "expected at least 2 args, got 1")]
    fn test_panic_one_arg() {
        let mut args = vec![Ok(LhsValue::Bytes(Cow::Borrowed(b"a=1&b=2")))].into_iter();
        remove_query_args_impl(&mut args);
    }
}
