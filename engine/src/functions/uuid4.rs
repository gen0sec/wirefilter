use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::borrow::Cow;

use super::{FunctionArgKind, FunctionArgs, FunctionDefinition};
use crate::{LhsValue, Type};
use std::iter;

/// Generates a random UUIDv4 (Universally Unique Identifier, version 4) based on the given argument (a source of randomness).
/// To obtain an array of random bytes, use the cf.random_seed field.
/// For example, uuidv4(cf.random_seed) will return a UUIDv4 similar to 49887398-6bcf-485f-8899-f15dbef4d1d5.
#[derive(Debug, Default)]
pub struct UUID4Function {}

#[inline]
fn uuid4_impl<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let arg = args.next().expect("expected 1 argument, got 0");

    if args.next().is_some() {
        panic!("expected 1 argument, got {}", 2 + args.count());
    }

    match arg {
        Ok(LhsValue::Bytes(bytes)) => {
            if bytes.len() < 16 {
                return None;
            }

            let mut seed: u64 = 0;
            for (i, &byte) in bytes.iter().enumerate() {
                seed ^= (byte as u64) << ((i % 8) * 8);
                seed = seed.rotate_left(7);
            }

            seed ^= bytes.len() as u64;

            let mut rng = StdRng::seed_from_u64(seed);

            let mut uuid_bytes = [0u8; 16];
            rng.fill(&mut uuid_bytes);

            uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40;

            uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80;

            let uuid_string = format!(
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                uuid_bytes[0],
                uuid_bytes[1],
                uuid_bytes[2],
                uuid_bytes[3],
                uuid_bytes[4],
                uuid_bytes[5],
                uuid_bytes[6],
                uuid_bytes[7],
                uuid_bytes[8],
                uuid_bytes[9],
                uuid_bytes[10],
                uuid_bytes[11],
                uuid_bytes[12],
                uuid_bytes[13],
                uuid_bytes[14],
                uuid_bytes[15]
            );

            Some(LhsValue::Bytes(Cow::Owned(uuid_string.into_bytes())))
        }
        Err(Type::Bytes) => None,
        _ => unreachable!(),
    }
}

impl FunctionDefinition for UUID4Function {
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
        Box::new(uuid4_impl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid4_fn() {
        // Test with some seed bytes
        let seed_bytes = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0";
        let mut args = vec![Ok(LhsValue::Bytes(Cow::Borrowed(seed_bytes)))].into_iter();

        let result = uuid4_impl(&mut args);
        assert!(result.is_some());

        if let Some(LhsValue::Bytes(uuid_string)) = result {
            let uuid_str = String::from_utf8(uuid_string.to_vec()).unwrap();
            // Check basic UUID format (8-4-4-4-12)
            assert_eq!(uuid_str.len(), 36);
            assert_eq!(uuid_str.chars().nth(8), Some('-'));
            assert_eq!(uuid_str.chars().nth(13), Some('-'));
            assert_eq!(uuid_str.chars().nth(18), Some('-'));
            assert_eq!(uuid_str.chars().nth(23), Some('-'));

            // Check version (4) - should be '4' at position 14
            assert_eq!(uuid_str.chars().nth(14), Some('4'));

            // Check variant bits - character at position 19 should be 8, 9, a, or b
            let variant_char = uuid_str.chars().nth(19).unwrap();
            assert!(matches!(variant_char, '8' | '9' | 'a' | 'b'));
        } else {
            panic!("Expected Bytes result");
        }
    }

    #[test]
    fn test_uuid4_fn_deterministic() {
        // Test that same seed produces same UUID (deterministic)
        let seed_bytes = b"test_seed_12345";

        let mut args1 = vec![Ok(LhsValue::Bytes(Cow::Borrowed(seed_bytes)))].into_iter();
        let result1 = uuid4_impl(&mut args1);

        let mut args2 = vec![Ok(LhsValue::Bytes(Cow::Borrowed(seed_bytes)))].into_iter();
        let result2 = uuid4_impl(&mut args2);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_uuid4_fn_different_seeds() {
        // Test that different seeds produce different UUIDs
        let seed1 = b"seed1";
        let seed2 = b"seed2";

        let mut args1 = vec![Ok(LhsValue::Bytes(Cow::Borrowed(seed1)))].into_iter();
        let result1 = uuid4_impl(&mut args1);

        let mut args2 = vec![Ok(LhsValue::Bytes(Cow::Borrowed(seed2)))].into_iter();
        let result2 = uuid4_impl(&mut args2);

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_uuid4_fn_short_seed() {
        // Test with a single byte seed (should work)
        let short_seed = b"a";
        let mut args = vec![Ok(LhsValue::Bytes(Cow::Borrowed(short_seed)))].into_iter();

        let result = uuid4_impl(&mut args);
        assert!(result.is_some());

        if let Some(LhsValue::Bytes(uuid_string)) = result {
            let uuid_str = String::from_utf8(uuid_string.to_vec()).unwrap();
            // Should still generate a proper UUID format
            assert_eq!(uuid_str.len(), 36);
            // Version should be 4
            assert_eq!(uuid_str.chars().nth(14), Some('4'));
        }
    }

    #[test]
    fn test_uuid4_fn_empty_bytes() {
        // Test with empty bytes (should return None now)
        let empty_bytes = b"";
        let mut args = vec![Ok(LhsValue::Bytes(Cow::Borrowed(empty_bytes)))].into_iter();

        let result = uuid4_impl(&mut args);
        assert_eq!(result, None);
    }

    #[test]
    fn test_uuid4_fn_long_seed() {
        // Test with a long seed (should work with any length)
        let long_seed = b"this_is_a_very_long_seed_with_many_bytes_to_test_entropy_mixing";
        let mut args = vec![Ok(LhsValue::Bytes(Cow::Borrowed(long_seed)))].into_iter();

        let result = uuid4_impl(&mut args);
        assert!(result.is_some());

        if let Some(LhsValue::Bytes(uuid_string)) = result {
            let uuid_str = String::from_utf8(uuid_string.to_vec()).unwrap();
            // Should generate a proper UUID format
            assert_eq!(uuid_str.len(), 36);
            // Version should be 4
            assert_eq!(uuid_str.chars().nth(14), Some('4'));
        }
    }

    #[test]
    fn test_uuid4_fn_missing_field() {
        // Test with missing field
        let mut args = vec![Err(Type::Bytes)].into_iter();
        assert_eq!(uuid4_impl(&mut args), None);
    }

    #[test]
    #[should_panic(expected = "expected 1 argument, got 0")]
    fn test_uuid4_fn_no_args() {
        let mut args = vec![].into_iter();
        uuid4_impl(&mut args);
    }

    #[test]
    #[should_panic(expected = "expected 1 argument, got 2")]
    fn test_uuid4_fn_too_many_args() {
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(b"a"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"b"))),
        ]
        .into_iter();
        uuid4_impl(&mut args);
    }
}
