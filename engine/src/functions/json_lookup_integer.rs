use std::iter;

use crate::{LhsValue, Type};

use super::{FunctionArgKind, FunctionArgs, FunctionDefinition};

/// Returns the integer value associated with the supplied key in `field`.
///
/// The `field` must be a string containing a valid JSON document. Subsequent
/// arguments are literal keys that can be attribute names (strings) or
/// zero-based array positions (integers). Keys are applied in order to traverse
/// the JSON hierarchy. Only plain integers are returned (floats like `42.0`
/// are rejected).
#[derive(Debug, Default)]
pub struct JsonLookupIntegerFunction {}

#[inline]
fn json_lookup_integer_impl<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let source_arg = args.next().expect("expected at least 2 arguments, got 0");
    let first_key = args.next().expect("expected at least 2 arguments, got 1");

    // the rest of `args` are optional additional keys

    let json_value = match source_arg {
        Ok(LhsValue::Bytes(bytes)) => match std::str::from_utf8(bytes.as_ref()) {
            Ok(s) => match serde_json::from_str::<serde_json::Value>(s) {
                Ok(v) => v,
                Err(_) => return None,
            },
            Err(_) => return None,
        },
        Err(Type::Bytes) => return None,
        _ => unreachable!(),
    };

    let mut current = json_value;

    let mut process_key = |arg: Result<LhsValue<'_>, Type>| -> Option<()> {
        match arg {
            Ok(LhsValue::Bytes(key_bytes)) => {
                let key = match std::str::from_utf8(key_bytes.as_ref()) {
                    Ok(s) => s,
                    Err(_) => return None,
                };
                match current {
                    serde_json::Value::Object(ref map) => {
                        if let Some(v) = map.get(key) {
                            current = v.clone();
                            Some(())
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }
            Ok(LhsValue::Int(i)) => {
                if i < 0 {
                    return None;
                }
                let idx = i as usize;
                match current {
                    serde_json::Value::Array(ref arr) => {
                        if idx < arr.len() {
                            current = arr[idx].clone();
                            Some(())
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }
            Err(Type::Bytes) | Err(Type::Int) => None,
            _ => unreachable!(),
        }
    };

    process_key(first_key)?;

    for arg in args {
        process_key(arg)?;
    }

    current.as_i64().map(LhsValue::Int)
}

impl FunctionDefinition for JsonLookupIntegerFunction {
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
            _ => {
                next_param.arg_kind().expect(FunctionArgKind::Literal)?;
                next_param
                    .expect_val_type(vec![Type::Bytes.into(), Type::Int.into()].into_iter())?;
            }
        }

        Ok(())
    }

    fn return_type(
        &self,
        _: &mut dyn ExactSizeIterator<Item = super::FunctionParam<'_>>,
        _: Option<&super::FunctionDefinitionContext>,
    ) -> crate::Type {
        Type::Int
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
        Box::new(json_lookup_integer_impl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn test_lookup_json_integer_basic() {
        let json = r#"{ "record_id": "aed53a", "version": 2 }"#;
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(json.as_bytes()))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"version"))),
        ]
        .into_iter();
        assert_eq!(json_lookup_integer_impl(&mut args), Some(LhsValue::Int(2)));
    }

    #[test]
    fn test_lookup_json_integer_basic_negative() {
        let json = r#"{ "record_id": "aed53a", "version": -2 }"#;
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(json.as_bytes()))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"version"))),
        ]
        .into_iter();
        assert_eq!(json_lookup_integer_impl(&mut args), Some(LhsValue::Int(-2)));
    }

    #[test]
    fn test_lookup_json_integer_nested() {
        let json = r#"{ "product": { "id": 356 } }"#;
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(json.as_bytes()))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"product"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"id"))),
        ]
        .into_iter();
        assert_eq!(
            json_lookup_integer_impl(&mut args),
            Some(LhsValue::Int(356))
        );
    }

    #[test]
    fn test_lookup_json_integer_array_root() {
        let json = r#"["first_item", -234]"#;
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(json.as_bytes()))),
            Ok(LhsValue::Int(1)),
        ]
        .into_iter();
        assert_eq!(
            json_lookup_integer_impl(&mut args),
            Some(LhsValue::Int(-234))
        );
    }

    #[test]
    fn test_lookup_json_integer_array_in_object() {
        let json = r#"{ "network_ids": [123, 456] }"#;
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(json.as_bytes()))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"network_ids"))),
            Ok(LhsValue::Int(0)),
        ]
        .into_iter();
        assert_eq!(
            json_lookup_integer_impl(&mut args),
            Some(LhsValue::Int(123))
        );
    }

    #[test]
    fn test_lookup_json_integer_array_of_objects() {
        let json = r#"[{ "product_id": 123 }, { "product_id": 456 }]"#;
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(json.as_bytes()))),
            Ok(LhsValue::Int(1)),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"product_id"))),
        ]
        .into_iter();
        assert_eq!(
            json_lookup_integer_impl(&mut args),
            Some(LhsValue::Int(456))
        );
    }

    #[test]
    fn test_lookup_json_integer_non_integer_float() {
        let json = r#"{ "value": 42.0 }"#;
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(json.as_bytes()))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"value"))),
        ]
        .into_iter();
        assert_eq!(json_lookup_integer_impl(&mut args), None);
    }

    #[test]
    fn test_lookup_json_integer_invalid_json() {
        let json = b"not a json";
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(json))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"k"))),
        ]
        .into_iter();
        assert_eq!(json_lookup_integer_impl(&mut args), None);
    }
}
