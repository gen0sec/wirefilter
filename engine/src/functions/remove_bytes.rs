use std::borrow::Cow;

use crate::{LhsValue, Type};

use super::{FunctionArgKind, FunctionArgs, FunctionDefinition};

/// Removes all bytes that appear in the provided byte list from the source bytes.
///
/// The second argument is a literal byte list; any byte present in that list
/// will be removed from the source. For example, `remove_bytes(field, "abc")`
/// removes all `a`, `b`, and `c` bytes from `field`.
#[derive(Debug, Default)]
pub struct RemoveBytesFunction {}

#[inline]
fn remove_bytes_impl<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let source_arg = args.next().expect("expected 2 argument, got 0");
    let pattern_arg = args.next().expect("expected 2 arguments, got 1");

    if args.next().is_some() {
        panic!("expected 2 arguments, got {}", 3 + args.count());
    }

    match (source_arg, pattern_arg) {
        (Ok(LhsValue::Bytes(source)), Ok(LhsValue::Bytes(pattern_list))) => {
            let source_bytes = source.as_ref();
            let pattern_bytes = pattern_list.as_ref();

            if pattern_bytes.is_empty() {
                return Some(LhsValue::Bytes(Cow::Owned(source_bytes.to_vec())));
            }

            let mut to_remove = [false; 256];
            for b in pattern_bytes.iter() {
                to_remove[*b as usize] = true;
            }

            let mut res = Vec::with_capacity(source_bytes.len());
            for &b in source_bytes.iter() {
                if !to_remove[b as usize] {
                    res.push(b);
                }
            }

            Some(LhsValue::Bytes(Cow::Owned(res)))
        }
        (Err(Type::Bytes), _) => None,
        (_, Err(Type::Bytes)) => None,
        _ => unreachable!(),
    }
}

impl FunctionDefinition for RemoveBytesFunction {
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
            1 => {
                next_param.arg_kind().expect(FunctionArgKind::Literal)?;
                next_param.expect_val_type(std::iter::once(Type::Bytes.into()))?;
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
        (2, Some(0))
    }

    fn compile(
        &self,
        _: &mut dyn ExactSizeIterator<Item = super::FunctionParam<'_>>,
        _: Option<super::FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        Box::new(remove_bytes_impl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    fn owned_bytes(s: &str) -> LhsValue<'_> {
        LhsValue::Bytes(Cow::Owned(s.as_bytes().to_vec()))
    }

    #[test]
    fn test_remove_bytes_basic() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"cloudflare.com"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"."))),
        ]
        .into_iter();
        assert_eq!(
            remove_bytes_impl(&mut args),
            Some(owned_bytes("cloudflarecom"))
        );
    }

    #[test]
    fn test_remove_bytes_multibyte_pattern() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"a--b--c"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"-"))),
        ]
        .into_iter();
        assert_eq!(remove_bytes_impl(&mut args), Some(owned_bytes("abc")));
    }

    #[test]
    fn test_remove_multiple_bytes() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"ab1c2d3"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"123"))),
        ]
        .into_iter();
        assert_eq!(remove_bytes_impl(&mut args), Some(owned_bytes("abcd")));
    }

    #[test]
    fn test_remove_bytes_no_match() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"hello"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"z"))),
        ]
        .into_iter();
        assert_eq!(remove_bytes_impl(&mut args), Some(owned_bytes("hello")));
    }

    #[test]
    fn test_remove_bytes_empty_pattern() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"abc"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b""))),
        ]
        .into_iter();
        assert_eq!(remove_bytes_impl(&mut args), Some(owned_bytes("abc")));
    }

    #[test]
    #[should_panic(expected = "expected 2 argument, got 0")]
    fn test_panic_no_args() {
        let mut args = vec![].into_iter();
        remove_bytes_impl(&mut args);
    }

    #[test]
    fn test_bad_args() {
        let mut first_arg_error =
            vec![Err(Type::Bytes), Ok(LhsValue::Bytes(Cow::Borrowed(b"")))].into_iter();
        assert_eq!(remove_bytes_impl(&mut first_arg_error), None);

        let mut second_arg_error =
            vec![Ok(LhsValue::Bytes(Cow::Borrowed(b""))), Err(Type::Bytes)].into_iter();
        assert_eq!(remove_bytes_impl(&mut second_arg_error), None);
    }
}
