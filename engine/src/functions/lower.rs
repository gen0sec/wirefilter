use crate::lhs_types::Bytes;
use crate::{FunctionArgKind, FunctionArgs, FunctionDefinition, LhsValue, Type};
use std::iter;

/// Converts a string field to lowercase. Only uppercase ASCII bytes are converted. All other bytes are unaffected.
/// For example, if http.host is "WWW.cloudflare.com", then lower(http.host) == "www.cloudflare.com" will return true.
#[derive(Debug, Default)]
pub struct LowerFunction {}

/// Branch-free per chunk so that the scan vectorizes; `iter().any()` stops at
/// the first hit, which prevents that.
#[inline]
fn has_ascii_uppercase(bytes: &[u8]) -> bool {
    let (chunks, rest) = bytes.as_chunks::<32>();
    let in_chunks = chunks.iter().any(|chunk| {
        chunk
            .iter()
            .fold(0u8, |acc, &b| acc | u8::from(b.wrapping_sub(b'A') < 26))
            != 0
    });
    in_chunks || rest.iter().any(u8::is_ascii_uppercase)
}

#[inline]
fn lower_impl<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let arg = args.next().expect("expected 1 argument, got 0");

    if args.next().is_some() {
        panic!("expected 1 argument, got {}", 2 + args.count());
    }

    match arg {
        Ok(LhsValue::Bytes(bytes)) => {
            if !has_ascii_uppercase(&bytes) {
                return Some(LhsValue::Bytes(bytes));
            }
            let mut owned = bytes.into_owned();
            owned.make_ascii_lowercase();
            Some(LhsValue::Bytes(Bytes::Owned(owned)))
        }
        Err(Type::Bytes) => None,
        _ => unreachable!(),
    }
}

impl FunctionDefinition for LowerFunction {
    fn is_pure(&self) -> bool {
        true
    }

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
            Some(LhsValue::Bytes(Bytes::Owned(
                b"hello world".to_vec().into_boxed_slice()
            )))
        );

        // Test with a mixed-case string
        let mut args_mixed = vec![Ok(LhsValue::Bytes(Bytes::Borrowed(b"MiXeD CaSe")))].into_iter();
        assert_eq!(
            lower_impl(&mut args_mixed),
            Some(LhsValue::Bytes(Bytes::Owned(
                b"mixed case".to_vec().into_boxed_slice()
            )))
        );

        // Test with an already lowercase string
        let mut args_lower =
            vec![Ok(LhsValue::Bytes(Bytes::Borrowed(b"already lower")))].into_iter();
        assert_eq!(
            lower_impl(&mut args_lower),
            Some(LhsValue::Bytes(Bytes::Owned(
                b"already lower".to_vec().into_boxed_slice()
            )))
        );

        // Test with an empty string
        let mut args_empty = vec![Ok(LhsValue::Bytes(Bytes::Borrowed(b"")))].into_iter();
        assert_eq!(
            lower_impl(&mut args_empty),
            Some(LhsValue::Bytes(Bytes::Owned(
                b"".to_vec().into_boxed_slice()
            )))
        );

        // Test with missing field
        let mut args_missing = vec![Err(Type::Bytes)].into_iter();
        assert_eq!(lower_impl(&mut args_missing), None);
    }

    #[test]
    fn test_lower_unchanged_input_is_not_copied() {
        let mut args = vec![Ok(LhsValue::Bytes(Bytes::Borrowed(
            b"already lower \xc3\xa9 1",
        )))]
        .into_iter();
        let out = lower_impl(&mut args).unwrap();
        assert!(matches!(
            out,
            LhsValue::Bytes(Bytes::Borrowed(b"already lower \xc3\xa9 1"))
        ));

        let mut args = vec![Ok(LhsValue::Bytes(Bytes::Borrowed(b"")))].into_iter();
        let out = lower_impl(&mut args).unwrap();
        assert!(matches!(out, LhsValue::Bytes(Bytes::Borrowed(b""))));

        let owned = Bytes::Owned(b"already lower \xc3\xa9 1".to_vec().into_boxed_slice());
        let mut args = vec![Ok(LhsValue::Bytes(owned))].into_iter();
        let out = lower_impl(&mut args).unwrap();
        assert!(matches!(out, LhsValue::Bytes(Bytes::Owned(_))));
        assert_eq!(
            out,
            LhsValue::Bytes(Bytes::Borrowed(b"already lower \xc3\xa9 1"))
        );
    }

    #[test]
    fn test_lower_changes_ascii_only_in_place() {
        let mut args =
            vec![Ok(LhsValue::Bytes(Bytes::Borrowed(b"MiXeD \xc3\xa9 CaSe")))].into_iter();
        let out = lower_impl(&mut args).unwrap();
        assert!(matches!(out, LhsValue::Bytes(Bytes::Owned(_))));
        assert_eq!(
            out,
            LhsValue::Bytes(Bytes::Borrowed(b"mixed \xc3\xa9 case"))
        );

        // A change in the last byte only is still found.
        let mut args = vec![Ok(LhsValue::Bytes(Bytes::Borrowed(b"abc.D")))].into_iter();
        assert_eq!(
            lower_impl(&mut args),
            Some(LhsValue::Bytes(Bytes::Owned(
                b"abc.d".to_vec().into_boxed_slice()
            )))
        );
    }

    #[test]
    fn test_lower_finds_a_change_at_every_position() {
        for len in [1usize, 31, 32, 33, 64, 70] {
            for pos in 0..len {
                let mut input = vec![b'a'; len];
                input[pos] = b'Z';
                let mut expected = input.clone();
                expected.make_ascii_lowercase();
                let mut args = vec![Ok(LhsValue::Bytes(Bytes::Borrowed(&input)))].into_iter();
                let out = lower_impl(&mut args).unwrap();
                assert_eq!(
                    out,
                    LhsValue::Bytes(Bytes::Borrowed(&expected)),
                    "len {len} pos {pos}"
                );
            }
        }
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
