use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::{FunctionArgs, FunctionDefinition, LhsValue, Type};

/// Decodes a Base64-encoded string specified in `source`.
///
/// The `source` must be a field (not a literal). The function decodes using
/// the standard Base64 alphabet (RFC 4648) and returns the decoded bytes.
///
/// Example:
///
/// Given an HTTP header: `client_id: MTIzYWJj`
///
/// ```text
/// any(decode_base64(http.request.headers["client_id"][*])[*] eq "123abc")
/// ```
///
/// The above evaluates to true because `MTIzYWJj` decodes to `"123abc"`.
#[derive(Default, Debug)]
pub struct DecodeBase64Function {}

#[inline]
fn decode_base64_impl_inner<'a>(source: Cow<'_, [u8]>) -> Cow<'a, [u8]> {
    match STANDARD.decode(source.as_ref()) {
        Ok(decoded) => Cow::Owned(decoded),
        Err(_) => Cow::Owned(Vec::new()),
    }
}

#[inline]
fn decode_base64_impl<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let source = args.next().expect("expected 1 argument, got 0");

    if args.next().is_some() {
        panic!("expected exactly 1 arg, got {}", 2 + args.count());
    }

    match source {
        Ok(LhsValue::Bytes(b)) => Some(LhsValue::Bytes(decode_base64_impl_inner(b))),
        Err(Type::Bytes) => None,
        _ => unreachable!(),
    }
}

impl FunctionDefinition for DecodeBase64Function {
    fn check_param(
        &self,
        _: &crate::ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = super::FunctionParam<'_>>,
        next_param: &super::FunctionParam<'_>,
        _: Option<&mut super::FunctionDefinitionContext>,
    ) -> Result<(), super::FunctionParamError> {
        match params.len() {
            0 => {
                next_param.arg_kind().expect(super::FunctionArgKind::Field)?;
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
        Box::new(decode_base64_impl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned_bytes(s: &str) -> LhsValue<'_> {
        LhsValue::Bytes(Cow::Owned(s.as_bytes().to_vec()))
    }

    #[test]
    fn test_decode_base64_basic() {
        let mut args = vec![Ok(LhsValue::Bytes(Cow::Borrowed(b"MTIzYWJj")))].into_iter();
        assert_eq!(decode_base64_impl(&mut args), Some(owned_bytes("123abc")));
    }

    #[test]
    #[should_panic(expected = "expected 1 argument, got 0")]
    fn test_panic_no_args() {
        let mut args = vec![].into_iter();
        decode_base64_impl(&mut args);
    }

    #[test]
    #[should_panic(expected = "expected exactly 1 arg, got 2")]
    fn test_panic_more_args() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"MTIzYWJj"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"MTIzYWJj"))),
        ]
        .into_iter();
        decode_base64_impl(&mut args);
    }
}
