use std::borrow::Cow;

use crate::{LhsValue, Type};

use super::{FunctionArgKind, FunctionArgs, FunctionDefinition};

/// Convert an Integer, Boolean, or IP LHS value into its textual representation.
///
/// Usage:
///
/// to_string(field)
///
/// - `field` must be a non-literal field whose value is `Integer`, `Boolean`,
///   or `IP`. If the field is missing (type mismatch at runtime), the
///   function evaluates to `None` (propagates the missing field).
/// - The function returns the UTF-8 bytes of the textual representation of
///   the value (for example `5` -> "5", `true` -> "true", `1.2.3.4` ->
///   "1.2.3.4").
///
/// Examples:
///
/// Given a field `http.request.status_code` with integer value `200`:
///
/// ```text
/// any(to_string(http.request.status_code)[*] eq "200")
/// ```
///
/// If the field is missing or has the wrong type at evaluation time the
/// function returns `None` and the surrounding expression will behave
/// accordingly.
#[derive(Debug, Default)]
pub struct ToStringFunction {}

#[inline]
fn to_string_impl<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let arg = args.next().expect("expected 1 argument, got 0");

    if args.next().is_some() {
        panic!("expected 1 argument, got {}", 2 + args.count());
    }

    match arg {
        Ok(LhsValue::Int(i)) => Some(LhsValue::Bytes(Cow::Owned(i.to_string().into_bytes()))),
        Ok(LhsValue::Bool(b)) => Some(LhsValue::Bytes(Cow::Owned(b.to_string().into_bytes()))),
        Ok(LhsValue::Ip(ip)) => Some(LhsValue::Bytes(Cow::Owned(ip.to_string().into_bytes()))),
        Err(Type::Int) | Err(Type::Bool) | Err(Type::Ip) => None,
        _ => unreachable!(),
    }
}

impl FunctionDefinition for ToStringFunction {
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
                next_param.expect_val_type(
                    [Type::Int.into(), Type::Bool.into(), Type::Ip.into()].into_iter(),
                )?;
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
        (1, Some(0))
    }

    fn compile(
        &self,
        _: &mut dyn ExactSizeIterator<Item = super::FunctionParam<'_>>,
        _: Option<super::FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        Box::new(to_string_impl)
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
    fn test_to_string_int() {
        let mut args = vec![Ok(LhsValue::Int(5))].into_iter();
        assert_eq!(to_string_impl(&mut args), Some(owned("5")));
    }

    #[test]
    fn test_to_string_bool() {
        let mut args = vec![Ok(LhsValue::Bool(true))].into_iter();
        assert_eq!(to_string_impl(&mut args), Some(owned("true")));
    }

    #[test]
    fn test_to_string_ip() {
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let mut args = vec![Ok(LhsValue::Ip(ip))].into_iter();
        assert_eq!(to_string_impl(&mut args), Some(owned("1.2.3.4")));
    }

    #[test]
    fn test_missing_field() {
        let mut args = vec![Err(Type::Int)].into_iter();
        assert_eq!(to_string_impl(&mut args), None);
    }

    #[test]
    #[should_panic(expected = "expected 1 argument, got 0")]
    fn test_panic_no_args() {
        let mut args = vec![].into_iter();
        to_string_impl(&mut args);
    }
}
