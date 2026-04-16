use std::iter;

use crate::lhs_types::Bytes;
use crate::{FunctionArgKind, FunctionArgs, FunctionDefinition, LhsValue, Type};

/// Converts a string field to lowercase. Only uppercase ASCII bytes are converted. All other bytes are unaffected.
/// For example, if http.host is "WWW.cloudflare.com", then lower(http.host) == "www.cloudflare.com" will return true.
#[derive(Debug, Default)]
pub struct LowerFunction {}

#[inline]
fn lower_impl<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let arg = args.next().expect("expected 1 argument, got 0");

    if args.next().is_some() {
        panic!("expected 1 argument, got {}", 2 + args.count());
    }

    match arg {
        Ok(LhsValue::Bytes(bytes)) => {
            let bytes_lower: Vec<u8> = bytes.into_owned().to_vec();
            let bytes_lower = bytes_lower.to_ascii_lowercase();
            Some(LhsValue::Bytes(Bytes::Owned(bytes_lower.into_boxed_slice())))
        }
        Err(Type::Bytes) => None,
        _ => unreachable!(),
    }
}

impl FunctionDefinition for LowerFunction {
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
        Box::new(lower_impl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lower_fn() {
        // Test with an all-uppercase string
        let mut args_upper = vec![Ok(LhsValue::Bytes(Bytes::Borrowed(b"HELLO WORLD")))].into_iter();
        assert_eq!(
            lower_impl(&mut args_upper),
            Some(LhsValue::Bytes(Bytes::Owned(b"hello world".to_vec().into_boxed_slice())))
        );

        // Test with a mixed-case string
        let mut args_mixed = vec![Ok(LhsValue::Bytes(Bytes::Borrowed(b"MiXeD CaSe")))].into_iter();
        assert_eq!(
            lower_impl(&mut args_mixed),
            Some(LhsValue::Bytes(Bytes::Owned(b"mixed case".to_vec().into_boxed_slice())))
        );

        // Test with an already lowercase string
        let mut args_lower = vec![Ok(LhsValue::Bytes(Bytes::Borrowed(b"already lower")))].into_iter();
        assert_eq!(
            lower_impl(&mut args_lower),
            Some(LhsValue::Bytes(Bytes::Owned(b"already lower".to_vec().into_boxed_slice())))
        );

        // Test with an empty string
        let mut args_empty = vec![Ok(LhsValue::Bytes(Bytes::Borrowed(b"")))].into_iter();
        assert_eq!(
            lower_impl(&mut args_empty),
            Some(LhsValue::Bytes(Bytes::Owned(b"".to_vec().into_boxed_slice())))
        );

        // Test with missing field
        let mut args_missing = vec![Err(Type::Bytes)].into_iter();
        assert_eq!(lower_impl(&mut args_missing), None);
    }

    #[test]
    #[should_panic(expected = "expected 1 argument, got 0")]
    fn test_lower_fn_no_args() {
        let mut args = vec![].into_iter();
        lower_impl(&mut args);
    }

    #[test]
    #[should_panic(expected = "expected 1 argument, got 2")]
    fn test_lower_fn_too_many_args() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"a"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"b"))),
        ]
        .into_iter();
        lower_impl(&mut args);
    }
}
