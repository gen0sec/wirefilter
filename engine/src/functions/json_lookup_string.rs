use std::iter;

use crate::{LhsValue, Type};

use super::{FunctionArgKind, FunctionArgs, FunctionDefinition};

/// Returns the string value associated with the supplied key in `field`.
///
/// The `field` must be a string containing a valid JSON document. Subsequent
/// arguments are literal keys that can be attribute names (strings) or
/// zero-based array positions (integers). Keys are applied in order to traverse
/// the JSON hierarchy. Only JSON string values are returned (other types yield None).
#[derive(Default, Debug)]
pub struct JsonLookupStringFunction {}

#[inline]
fn json_lookup_string_impl<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let source_arg = args.next().expect("expected at least 2 arguments, got 0");
    let first_key = args.next().expect("expected at least 2 arguments, got 1");

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

    if process_key(first_key).is_none() {
        return None;
    }

    for arg in args {
        if process_key(arg).is_none() {
            return None;
        }
    }

    match current.as_str() {
        Some(s) => Some(LhsValue::Bytes(std::borrow::Cow::Owned(
            s.as_bytes().to_vec(),
        ))),
        None => None,
    }
}

impl FunctionDefinition for JsonLookupStringFunction {
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
        Box::new(json_lookup_string_impl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn test_lookup_json_string_basic() {
        let json = r#"{ "company": "cloudflare", "product": "rulesets" }"#;
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(json.as_bytes()))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"company"))),
        ]
        .into_iter();
        assert_eq!(
            json_lookup_string_impl(&mut args),
            Some(LhsValue::Bytes(Cow::Owned(b"cloudflare".to_vec())))
        );
    }

    #[test]
    fn test_lookup_json_string_nested() {
        let json = r#"{ "network": { "name": "cloudflare" } }"#;
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(json.as_bytes()))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"network"))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"name"))),
        ]
        .into_iter();
        assert_eq!(
            json_lookup_string_impl(&mut args),
            Some(LhsValue::Bytes(Cow::Owned(b"cloudflare".to_vec())))
        );
    }

    #[test]
    fn test_lookup_json_string_array_root() {
        let json = r#"["other_company", "cloudflare"]"#;
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(json.as_bytes()))),
            Ok(LhsValue::Int(1)),
        ]
        .into_iter();
        assert_eq!(
            json_lookup_string_impl(&mut args),
            Some(LhsValue::Bytes(Cow::Owned(b"cloudflare".to_vec())))
        );
    }

    #[test]
    fn test_lookup_json_string_array_in_object() {
        let json = r#"{ "networks": ["other_company", "cloudflare"] }"#;
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(json.as_bytes()))),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"networks"))),
            Ok(LhsValue::Int(1)),
        ]
        .into_iter();
        assert_eq!(
            json_lookup_string_impl(&mut args),
            Some(LhsValue::Bytes(Cow::Owned(b"cloudflare".to_vec())))
        );
    }

    #[test]
    fn test_lookup_json_string_array_of_objects() {
        let json = r#"[{ "network": "other_company" }, { "network": "cloudflare" }]"#;
        let mut args = vec![
            Ok(LhsValue::Bytes(Cow::Borrowed(json.as_bytes()))),
            Ok(LhsValue::Int(1)),
            Ok(LhsValue::Bytes(Cow::Borrowed(b"network"))),
        ]
        .into_iter();
        assert_eq!(
            json_lookup_string_impl(&mut args),
            Some(LhsValue::Bytes(Cow::Owned(b"cloudflare".to_vec())))
        );
    }
}
