use crate::lhs_types::Bytes;
use crate::{FunctionArgs, FunctionDefinition, LhsValue, Type};
use std::iter;

/// Decodes a URL-formatted string defined in source.
///
/// Behavior summary:
/// - `%20` and `+` decode to a space character (` `).
/// - `%HH` decodes to the corresponding byte value.
/// - `%uXXXX` (when the `u` option is provided) decodes to the Unicode
///   code point U+XXXX and is emitted as UTF-8 bytes.
/// - The source must be a field (not a literal string).
///
/// Options (passed as a single literal string, e.g. "r" or "ur"):
/// - `r`: Recursive decoding. For example `%2520` decoded with `r` becomes a space
///   (`%2520` -> `%20` -> ` `).
/// - `u`: Enable Unicode percent decoding using `%uXXXX` sequences. The output
///   will be UTF-8 encoded.
///
/// Examples:
///
/// url_decode("John%20Doe") -> "John Doe"
/// url_decode("John+Doe")   -> "John Doe"
/// url_decode("%2520")      -> "%20"
/// url_decode("%2520", "r") -> " "
///
/// Notes:
/// - If `u` is provided and a `%uXXXX` sequence contains an invalid code point
///   or invalid hex, the implementation falls back conservatively and leaves
///   the `%` byte intact for that sequence.
/// - Recursive decoding is bounded (to avoid pathological loops).
#[derive(Debug, Default)]
pub struct UrlDecodeFunction {}

/// Decodes one pass. The flag is true when at least one `+` or escape was
/// decoded, which always changes the bytes.
fn decode_once(input: &[u8], unicode_u: bool) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(input.len());
    let mut changed = false;
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'+' => {
                out.push(b' ');
                changed = true;
                i += 1;
            }
            b'%' => {
                if unicode_u
                    && i + 5 < input.len()
                    && (input[i + 1] == b'u' || input[i + 1] == b'U')
                {
                    let hex = &input[i + 2..i + 6];
                    if let Some(encoded) = std::str::from_utf8(hex)
                        .ok()
                        .and_then(|s| u32::from_str_radix(s, 16).ok())
                        .and_then(std::char::from_u32)
                        .map(|ch| {
                            let mut buf = [0u8; 4];
                            ch.encode_utf8(&mut buf).as_bytes().to_vec()
                        })
                    {
                        out.extend_from_slice(&encoded);
                        changed = true;
                        i += 6;
                        continue;
                    }
                    out.push(b'%');
                    i += 1;
                } else if i + 2 < input.len() {
                    // parse %HH
                    let hex = &input[i + 1..i + 3];
                    if let Some(byte) = std::str::from_utf8(hex)
                        .ok()
                        .and_then(|s| u8::from_str_radix(s, 16).ok())
                    {
                        out.push(byte);
                        changed = true;
                        i += 3;
                        continue;
                    }
                    out.push(b'%');
                    i += 1;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    (out, changed)
}

#[inline]
fn url_decode<'a>(source: Bytes<'a>, options: Option<&[u8]>) -> Bytes<'a> {
    let mut recursive = false;
    let mut unicode_u = false;
    if let Some(opts) = options {
        for &b in opts {
            match b {
                b'r' => recursive = true,
                b'u' => unicode_u = true,
                _ => {}
            }
        }
    }

    if memchr::memchr2(b'%', b'+', &source).is_none() {
        return source;
    }

    let (mut current, changed) = decode_once(&source, unicode_u);
    if !changed {
        return source;
    }

    if recursive {
        // At most 10 passes in total, as before: the first one is done above.
        for _ in 0..9 {
            let (next, changed) = decode_once(&current, unicode_u);
            if !changed {
                break;
            }
            current = next;
        }
    }
    Bytes::Owned(current.into_boxed_slice())
}

#[inline]
fn url_decode_impl<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let source_arg = args.next().expect("expected 1 argument, got 0");
    let options_arg = args.next();

    if args.next().is_some() {
        panic!("expected maximum 2 args, got {}", 3 + args.count());
    }

    match (source_arg, options_arg) {
        (_, Some(Err(Type::Bytes))) => None,
        (Ok(LhsValue::Bytes(source)), opt) => {
            // Extract options bytes into an owned buffer to avoid lifetime issues
            let opts_bytes: Option<Vec<u8>> = match opt {
                Some(Ok(LhsValue::Bytes(b))) => Some(b.as_ref().to_vec()),
                _ => None,
            };
            let decoded = url_decode(source, opts_bytes.as_deref());
            Some(LhsValue::Bytes(decoded))
        }
        (Err(Type::Bytes), _) => None,
        _ => unreachable!(),
    }
}

impl FunctionDefinition for UrlDecodeFunction {
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
                next_param
                    .arg_kind()
                    .expect(super::FunctionArgKind::Field)?;
                next_param.expect_val_type(iter::once(Type::Bytes.into()))?;
            }
            1 => {
                next_param
                    .arg_kind()
                    .expect(super::FunctionArgKind::Literal)?;
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
        (1, Some(1))
    }

    fn compile(
        &self,
        _: &mut dyn ExactSizeIterator<Item = super::FunctionParam<'_>>,
        _: Option<super::FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        Box::new(url_decode_impl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lhs_types::Bytes;

    fn owned_bytes(s: &str) -> LhsValue<'_> {
        LhsValue::Bytes(Bytes::Owned(s.as_bytes().to_vec().into_boxed_slice()))
    }

    #[test]
    fn test_url_decode_basic() {
        let mut args = vec![Ok(LhsValue::Bytes(Bytes::Borrowed(b"John%20Doe")))].into_iter();
        assert_eq!(url_decode_impl(&mut args), Some(owned_bytes("John Doe")));

        let mut args = vec![Ok(LhsValue::Bytes(Bytes::Borrowed(b"John+Doe")))].into_iter();
        assert_eq!(url_decode_impl(&mut args), Some(owned_bytes("John Doe")));

        let mut args = vec![Ok(LhsValue::Bytes(Bytes::Borrowed(b"%2520")))].into_iter();
        // without recursive flag -> "%20"
        assert_eq!(url_decode_impl(&mut args), Some(owned_bytes("%20")));

        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"%2520"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"r"))),
        ]
        .into_iter();
        assert_eq!(url_decode_impl(&mut args), Some(owned_bytes(" ")));
    }

    #[test]
    fn test_url_decode_unicode_u() {
        // %u2601 -> U+2601 (cloud)
        let mut args = vec![
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"%u2601"))),
            Ok(LhsValue::Bytes(Bytes::Borrowed(b"u"))),
        ]
        .into_iter();
        let res = url_decode_impl(&mut args).unwrap();
        if let LhsValue::Bytes(b) = res {
            assert_eq!(b.into_owned(), "☁".as_bytes().to_vec().into_boxed_slice());
        } else {
            panic!("expected bytes")
        }
    }

    // The algorithm as it was before the fast paths, kept verbatim as an oracle.
    fn old_decode_once(input: &[u8], unicode_u: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            match input[i] {
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b'%' => {
                    if unicode_u
                        && i + 5 < input.len()
                        && (input[i + 1] == b'u' || input[i + 1] == b'U')
                    {
                        let hex = &input[i + 2..i + 6];
                        if let Some(encoded) = std::str::from_utf8(hex)
                            .ok()
                            .and_then(|s| u32::from_str_radix(s, 16).ok())
                            .and_then(std::char::from_u32)
                            .map(|ch| {
                                let mut buf = [0u8; 4];
                                ch.encode_utf8(&mut buf).as_bytes().to_vec()
                            })
                        {
                            out.extend_from_slice(&encoded);
                            i += 6;
                            continue;
                        }
                        out.push(b'%');
                        i += 1;
                    } else if i + 2 < input.len() {
                        // parse %HH
                        let hex = &input[i + 1..i + 3];
                        if let Some(byte) = std::str::from_utf8(hex)
                            .ok()
                            .and_then(|s| u8::from_str_radix(s, 16).ok())
                        {
                            out.push(byte);
                            i += 3;
                            continue;
                        }
                        out.push(b'%');
                        i += 1;
                    } else {
                        out.push(b'%');
                        i += 1;
                    }
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        out
    }

    fn old_url_decode(source: &[u8], options: Option<&[u8]>) -> Bytes<'static> {
        let mut recursive = false;
        let mut unicode_u = false;
        if let Some(opts) = options {
            for &b in opts {
                match b {
                    b'r' => recursive = true,
                    b'u' => unicode_u = true,
                    _ => {}
                }
            }
        }

        let mut current = source.to_vec();

        let mut next = old_decode_once(&current, unicode_u);

        if recursive {
            for _ in 0..10 {
                if next == current {
                    break;
                }
                current = next;
                next = old_decode_once(&current, unicode_u);
            }
            Bytes::Owned(current.into_boxed_slice())
        } else {
            Bytes::Owned(next.into_boxed_slice())
        }
    }

    fn run(input: &[u8], flag: &str) -> Vec<u8> {
        let opts = if flag.is_empty() {
            None
        } else {
            Some(flag.as_bytes())
        };
        url_decode(Bytes::Borrowed(input), opts).to_vec()
    }

    const FLAGS: [&str; 4] = ["", "r", "u", "ur"];

    #[test]
    fn url_decode_matches_old_on_crafted_inputs() {
        let deep = format!("%{}41", "25".repeat(12));
        let deep_u = format!("%{}u0041", "25".repeat(12));
        let crafted = [
            "",
            "plain",
            "+",
            "a+b++c",
            "%2B",
            "%25",
            "%2525",
            "%252525",
            "%zz",
            "%4",
            "abc%4",
            "%",
            "%%",
            "%u0041",
            "%U0041",
            "%25u0041",
            "%u00",
            "%uzzzz",
            "%ud800",
            "%25252541",
            deep.as_str(),
            deep_u.as_str(),
        ];
        for input in crafted {
            for flag in FLAGS {
                assert_eq!(
                    run(input.as_bytes(), flag),
                    old_url_decode(input.as_bytes(), Some(flag.as_bytes())).to_vec(),
                    "input {input:?} flag {flag:?}"
                );
            }
        }
    }

    #[test]
    fn url_decode_matches_old_on_random_inputs() {
        const ALPHABET: &[u8] = b"%+2541uzA ";
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..1000 {
            let len = (next() % 40) as usize;
            let input: Vec<u8> = (0..len)
                .map(|_| ALPHABET[(next() % ALPHABET.len() as u64) as usize])
                .collect();
            for flag in FLAGS {
                assert_eq!(
                    run(&input, flag),
                    old_url_decode(&input, Some(flag.as_bytes())).to_vec(),
                    "input {:?} flag {flag:?}",
                    String::from_utf8_lossy(&input)
                );
            }
        }
    }

    #[test]
    fn url_decode_without_escapes_borrows() {
        for flag in [None, Some(&b"r"[..]), Some(&b"ur"[..])] {
            let mut v = vec![Ok(LhsValue::Bytes(Bytes::Borrowed(b"no escapes here")))];
            v.extend(flag.map(|f| Ok(LhsValue::Bytes(Bytes::Borrowed(f)))));
            let mut args = v.into_iter();
            let out = url_decode_impl(&mut args).unwrap();
            assert!(
                matches!(out, LhsValue::Bytes(Bytes::Borrowed(b"no escapes here"))),
                "flag {flag:?}: {out:?}"
            );
        }
    }

    #[test]
    #[should_panic(expected = "expected 1 argument, got 0")]
    fn test_panic_no_args() {
        let mut args = vec![].into_iter();
        url_decode_impl(&mut args);
    }
}
