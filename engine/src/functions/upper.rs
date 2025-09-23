use std::borrow::Cow;

use super::{FunctionArgKind, FunctionArgs, FunctionDefinition};
use crate::{LhsValue, Type};
use std::iter;

/// Converts a string field to uppercase. Only lowercase ASCII bytes are converted. All other bytes are unaffected.
/// For example, if http.host is "www.cloudflare.com", then upper(http.host) will return "WWW.CLOUDFLARE.COM".
#[derive(Debug, Default)]
pub struct UpperFunction {}

#[inline]
fn upper_impl<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let arg = args.next().expect("expected 1 argument, got 0");

    if args.next().is_some() {
        panic!("expected 1 argument, got {}", 2 + args.count());
    }

    match arg {
        Ok(LhsValue::Bytes(bytes)) => {
            let bytes_upper = bytes.into_owned().to_ascii_uppercase();
            Some(LhsValue::Bytes(Cow::Owned(bytes_upper)))
        }
        Err(Type::Bytes) => None,
        _ => unreachable!(),
    }
}

impl FunctionDefinition for UpperFunction {
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
    ) -> Type {
        Type::Bytes
    }

    fn arg_count(&self) -> (usize, Option<usize>) {
        (1, Some(0))
    }

    fn compile(
        &self,
        _: &mut dyn ExactSizeIterator<Item = super::FunctionParam<'_>>,
        _: Option<super::FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        Box::new(upper_impl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upper_fn() {
        // Test with an all-lowercase string
        let mut args_lower = vec![Ok(LhsValue::Bytes(Cow::Borrowed(b"hello world")))].into_iter();
        assert_eq!(
            upper_impl(&mut args_lower),
            Some(LhsValue::Bytes(Cow::Owned(b"HELLO WORLD".to_vec())))
        );

        // Test with a mixed-case string
        let mut args_mixed = vec![Ok(LhsValue::Bytes(Cow::Borrowed(b"MiXeD CaSe")))].into_iter();
        assert_eq!(
            upper_impl(&mut args_mixed),
            Some(LhsValue::Bytes(Cow::Owned(b"MIXED CASE".to_vec())))
        );

        // Test with an already uppercase string
        let mut args_upper = vec![Ok(LhsValue::Bytes(Cow::Borrowed(b"ALREADY UPPER")))].into_iter();
        assert_eq!(
            upper_impl(&mut args_upper),
            Some(LhsValue::Bytes(Cow::Owned(b"ALREADY UPPER".to_vec())))
        );

        // Test with the example from the specification: "www.cloudflare.com"
        let mut args_example =
            vec![Ok(LhsValue::Bytes(Cow::Borrowed(b"www.cloudflare.com")))].into_iter();
        assert_eq!(
            upper_impl(&mut args_example),
            Some(LhsValue::Bytes(Cow::Owned(b"WWW.CLOUDFLARE.COM".to_vec())))
        );

        // Test with an empty string
        let mut args_empty = vec![Ok(LhsValue::Bytes(Cow::Borrowed(b"")))].into_iter();
        assert_eq!(
            upper_impl(&mut args_empty),
            Some(LhsValue::Bytes(Cow::Owned(b"".to_vec())))
        );

        // Test with missing field
        let mut args_missing = vec![Err(Type::Bytes)].into_iter();
        assert_eq!(upper_impl(&mut args_missing), None);

        // Test that only ASCII lowercase bytes are converted, other bytes are unaffected
        let mut args_non_ascii =
            vec![Ok(LhsValue::Bytes(Cow::Borrowed(b"hello\xc3\xa9world")))].into_iter();
        assert_eq!(
            upper_impl(&mut args_non_ascii),
            Some(LhsValue::Bytes(Cow::Owned(b"HELLO\xc3\xa9WORLD".to_vec())))
        );
    }

    #[test]
    #[should_panic(expected = "expected 1 argument, got 0")]
    fn test_upper_fn_no_args() {
        let mut args = vec![].into_iter();
        upper_impl(&mut args);
    }

    #[test]
    #[should_panic(expected = "expected 1 argument, got 2")]
    fn test_upper_fn_too_many_args() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"a"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"b"))),
        ]
        .into_iter();
        upper_impl(&mut args);
    }
}
