//! `MemoCompiler` computes each pure function call once per execution
//! context. These tests count how often the function bodies really run.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use wirefilter::{
    AllFunction, AlwaysList, AnyFunction, Compiler, DefaultCompiler, ExecutionContext, Filter,
    FunctionArgs, FunctionDefinition, FunctionDefinitionContext, FunctionParam, FunctionParamError,
    LhsValue, LowerFunction, MemoCompiler, MemoLayout, ParserSettings, Scheme, SchemeBuilder,
    SetFieldValueError, Type, TypedArray, TypedMap, UpperFunction, UrlDecodeFunction,
};

/// Wraps a real function, counts executions and chooses its own purity.
#[derive(Debug)]
struct Counting<F> {
    inner: F,
    pure: bool,
    calls: Arc<AtomicUsize>,
}

impl<F: FunctionDefinition> Counting<F> {
    fn new(inner: F, pure: bool) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                inner,
                pure,
                calls: calls.clone(),
            },
            calls,
        )
    }
}

impl<F: FunctionDefinition> FunctionDefinition for Counting<F> {
    fn is_pure(&self) -> bool {
        self.pure
    }

    fn context(&self) -> Option<FunctionDefinitionContext> {
        self.inner.context()
    }

    fn check_param(
        &self,
        settings: &ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        next_param: &FunctionParam<'_>,
        ctx: Option<&mut FunctionDefinitionContext>,
    ) -> Result<(), FunctionParamError> {
        self.inner.check_param(settings, params, next_param, ctx)
    }

    fn return_type(
        &self,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        ctx: Option<&FunctionDefinitionContext>,
    ) -> Type {
        self.inner.return_type(params, ctx)
    }

    fn arg_count(&self) -> (usize, Option<usize>) {
        self.inner.arg_count()
    }

    fn compile(
        &self,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        ctx: Option<FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        let inner = self.inner.compile(params, ctx);
        let calls = self.calls.clone();
        Box::new(move |args| {
            calls.fetch_add(1, Ordering::SeqCst);
            inner(args)
        })
    }
}

struct Fixture {
    scheme: Scheme,
    lower: Arc<AtomicUsize>,
    upper: Arc<AtomicUsize>,
    decode: Arc<AtomicUsize>,
    impure_lower: Arc<AtomicUsize>,
    impure_upper: Arc<AtomicUsize>,
}

fn fixture() -> Fixture {
    let mut b = SchemeBuilder::new();
    b.add_field("a", Type::Bytes).unwrap();
    b.add_field("b", Type::Bytes).unwrap();
    b.add_field("arr", Type::Array(Type::Bytes.into())).unwrap();
    b.add_field("m", Type::Map(Type::Bytes.into())).unwrap();
    let (lower, lower_calls) = Counting::new(LowerFunction::default(), true);
    let (upper, upper_calls) = Counting::new(UpperFunction::default(), true);
    let (decode, decode_calls) = Counting::new(UrlDecodeFunction::default(), true);
    let (impure_lower, impure_lower_calls) = Counting::new(LowerFunction::default(), false);
    let (impure_upper, impure_upper_calls) = Counting::new(UpperFunction::default(), false);
    b.add_function("any", AnyFunction::default()).unwrap();
    b.add_function("all", AllFunction::default()).unwrap();
    b.add_function("cnt_lower", lower).unwrap();
    b.add_function("cnt_upper", upper).unwrap();
    b.add_function("cnt_decode", decode).unwrap();
    b.add_function("impure_lower", impure_lower).unwrap();
    b.add_function("impure_upper", impure_upper).unwrap();
    b.add_list(Type::Ip, AlwaysList {}).unwrap();
    Fixture {
        scheme: b.build(),
        lower: lower_calls,
        upper: upper_calls,
        decode: decode_calls,
        impure_lower: impure_lower_calls,
        impure_upper: impure_upper_calls,
    }
}

fn count(c: &Arc<AtomicUsize>) -> usize {
    c.load(Ordering::SeqCst)
}

fn memo_filters(scheme: &Scheme, exprs: &[&str]) -> (Vec<Filter>, MemoLayout) {
    let mut compiler = MemoCompiler::<()>::new();
    let filters = exprs
        .iter()
        .map(|e| {
            scheme
                .parse(e)
                .unwrap_or_else(|err| panic!("{e}: {err}"))
                .compile_with_compiler(&mut compiler)
        })
        .collect();
    (filters, compiler.layout())
}

fn default_filters(scheme: &Scheme, exprs: &[&str]) -> Vec<Filter> {
    let mut compiler = DefaultCompiler::<()>::new();
    exprs
        .iter()
        .map(|e| {
            scheme
                .parse(e)
                .unwrap()
                .compile_with_compiler(&mut compiler)
        })
        .collect()
}

fn set<'a>(
    ctx: &mut ExecutionContext<'a>,
    name: &str,
    v: &'a str,
) -> Result<(), SetFieldValueError> {
    let scheme = ctx.scheme().clone();
    ctx.set_field_value(scheme.get_field(name).unwrap(), v)
        .map(|_| ())
}

fn run_all(filters: &[Filter], ctx: &ExecutionContext<'_>) -> Vec<bool> {
    filters.iter().map(|f| f.execute(ctx).unwrap()).collect()
}

fn memo_ctx(scheme: &Scheme, layout: &MemoLayout) -> ExecutionContext<'static> {
    let mut ctx = ExecutionContext::new_with_memo(scheme, layout);
    set(&mut ctx, "a", "AbC").unwrap();
    set(&mut ctx, "b", "XyZ").unwrap();
    ctx
}

#[test]
fn shared_call_is_computed_once() {
    let f = fixture();
    let (filters, layout) = memo_filters(
        &f.scheme,
        &[r#"cnt_lower(a) == "abc""#, r#"cnt_lower(a) == "zzz""#],
    );
    let ctx = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &ctx), vec![true, false]);
    assert_eq!(count(&f.lower), 1);
    // A second pass over the same context reuses the slot too.
    assert_eq!(run_all(&filters, &ctx), vec![true, false]);
    assert_eq!(count(&f.lower), 1);
}

#[test]
fn default_compiler_does_not_memoize() {
    let f = fixture();
    let filters = default_filters(
        &f.scheme,
        &[r#"cnt_lower(a) == "abc""#, r#"cnt_lower(a) == "zzz""#],
    );
    let ctx = memo_ctx(&f.scheme, &MemoCompiler::<()>::new().layout());
    assert_eq!(run_all(&filters, &ctx), vec![true, false]);
    assert_eq!(count(&f.lower), 2);
}

#[test]
fn different_literal_or_flag_use_separate_slots() {
    let f = fixture();
    let (filters, layout) = memo_filters(
        &f.scheme,
        &[
            r#"cnt_decode(a, "r") == "A""#,
            r#"cnt_decode(a) == "%41""#,
            r#"cnt_decode(a, "u") == "%41""#,
            r#"cnt_decode(a, "r") == "A""#,
        ],
    );
    let mut ctx = ExecutionContext::new_with_memo(&f.scheme, &layout);
    set(&mut ctx, "a", "%2541").unwrap();
    set(&mut ctx, "b", "").unwrap();
    assert_eq!(run_all(&filters, &ctx), vec![true, true, true, true]);
    // Three distinct (flag) calls, the fourth filter shares with the first.
    assert_eq!(count(&f.decode), 3);
    assert_eq!(layout.slot_count(), 3);
}

#[test]
fn different_field_uses_separate_slots() {
    let f = fixture();
    let (filters, layout) = memo_filters(
        &f.scheme,
        &[r#"cnt_lower(a) == "abc""#, r#"cnt_lower(b) == "xyz""#],
    );
    let ctx = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &ctx), vec![true, true]);
    assert_eq!(count(&f.lower), 2);
}

#[test]
fn different_map_key_uses_separate_slots() {
    let f = fixture();
    let (filters, layout) = memo_filters(
        &f.scheme,
        &[
            r#"cnt_lower(m["x"]) == "vx""#,
            r#"cnt_lower(m["y"]) == "vy""#,
        ],
    );
    let mut ctx = memo_ctx(&f.scheme, &layout);
    let mut m = TypedMap::<&str>::new();
    m.insert(b"x".to_vec().into(), "VX");
    m.insert(b"y".to_vec().into(), "VY");
    ctx.set_field_value(f.scheme.get_field("m").unwrap(), m)
        .unwrap();
    assert_eq!(run_all(&filters, &ctx), vec![true, true]);
    assert_eq!(count(&f.lower), 2);
}

#[test]
fn different_function_uses_separate_slots() {
    let f = fixture();
    let (filters, layout) = memo_filters(
        &f.scheme,
        &[r#"cnt_lower(a) == "abc""#, r#"cnt_upper(a) == "ABC""#],
    );
    let ctx = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &ctx), vec![true, true]);
    assert_eq!(count(&f.lower), 1);
    assert_eq!(count(&f.upper), 1);
}

#[test]
fn nested_inner_call_is_shared() {
    let f = fixture();
    let (filters, layout) = memo_filters(
        &f.scheme,
        &[
            r#"cnt_lower(cnt_decode(a, "r")) == "a b""#,
            r#"cnt_upper(cnt_decode(a, "r")) == "A B""#,
        ],
    );
    let mut ctx = ExecutionContext::new_with_memo(&f.scheme, &layout);
    set(&mut ctx, "a", "A%2520B").unwrap();
    set(&mut ctx, "b", "").unwrap();
    assert_eq!(run_all(&filters, &ctx), vec![true, true]);
    assert_eq!(count(&f.decode), 1);
    assert_eq!(count(&f.lower), 1);
    assert_eq!(count(&f.upper), 1);
}

#[test]
fn array_results_are_cached() {
    let f = fixture();
    let (filters, layout) = memo_filters(
        &f.scheme,
        &[
            r#"any(cnt_lower(arr[*])[*] == "two")"#,
            r#"any(cnt_lower(arr[*])[*] == "three")"#,
            r#"any(cnt_lower(arr[*])[*] == "nope")"#,
        ],
    );
    let mut ctx = memo_ctx(&f.scheme, &layout);
    let mut arr = TypedArray::<&str>::new();
    for v in ["ONE", "TWO", "THREE"] {
        arr.push(v);
    }
    ctx.set_field_value(f.scheme.get_field("arr").unwrap(), arr)
        .unwrap();
    assert_eq!(run_all(&filters, &ctx), vec![true, true, false]);
    // Once per element, not once per element per filter.
    assert_eq!(count(&f.lower), 3);
}

#[test]
fn impure_call_is_not_cached() {
    let f = fixture();
    let (filters, layout) = memo_filters(
        &f.scheme,
        &[r#"impure_lower(a) == "abc""#, r#"impure_lower(a) == "abc""#],
    );
    let ctx = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &ctx), vec![true, true]);
    assert_eq!(count(&f.impure_lower), 2);
    assert_eq!(layout.slot_count(), 0);
}

#[test]
fn pure_call_over_impure_call_is_not_cached() {
    let f = fixture();
    let (filters, layout) = memo_filters(
        &f.scheme,
        &[
            r#"cnt_upper(impure_lower(a)) == "ABC""#,
            r#"cnt_upper(impure_lower(a)) == "ABC""#,
        ],
    );
    let ctx = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &ctx), vec![true, true]);
    assert_eq!(count(&f.impure_lower), 2);
    assert_eq!(count(&f.upper), 2);
    assert_eq!(layout.slot_count(), 0);
}

#[test]
fn impure_call_inside_pure_argument_position_is_not_cached() {
    // The impure call is not the outermost one, and sits two levels down.
    let f = fixture();
    let (filters, layout) = memo_filters(
        &f.scheme,
        &[
            r#"cnt_lower(cnt_upper(impure_upper(a))) == "abc""#,
            r#"cnt_lower(cnt_upper(impure_upper(a))) == "abc""#,
        ],
    );
    let ctx = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &ctx), vec![true, true]);
    assert_eq!(count(&f.impure_upper), 2);
    assert_eq!(count(&f.lower), 2);
}

#[test]
fn cached_error_is_recomputed_after_set_field_value() {
    let f = fixture();
    let (filters, layout) = memo_filters(&f.scheme, &[r#"cnt_lower(m["x"]) == "v""#]);
    let mut ctx = memo_ctx(&f.scheme, &layout);
    let mut empty = TypedMap::<&str>::new();
    empty.insert(b"other".to_vec().into(), "V");
    ctx.set_field_value(f.scheme.get_field("m").unwrap(), empty)
        .unwrap();
    assert_eq!(run_all(&filters, &ctx), vec![false]);
    assert_eq!(run_all(&filters, &ctx), vec![false]);
    assert_eq!(count(&f.lower), 1, "the Err is cached");

    let mut m = TypedMap::<&str>::new();
    m.insert(b"x".to_vec().into(), "V");
    ctx.set_field_value(f.scheme.get_field("m").unwrap(), m)
        .unwrap();
    assert_eq!(run_all(&filters, &ctx), vec![true]);
    assert_eq!(count(&f.lower), 2);
}

#[test]
fn set_field_value_recomputes_with_the_new_value() {
    let f = fixture();
    let (filters, layout) = memo_filters(&f.scheme, &[r#"cnt_lower(a) == "abc""#]);
    let mut ctx = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &ctx), vec![true]);
    set(&mut ctx, "a", "OTHER").unwrap();
    assert_eq!(run_all(&filters, &ctx), vec![false]);
    assert_eq!(count(&f.lower), 2);
    ctx.set_field_value_from_name("a", "ABC").unwrap();
    assert_eq!(run_all(&filters, &ctx), vec![true]);
    assert_eq!(count(&f.lower), 3);
}

#[test]
fn failed_set_field_value_keeps_the_cache() {
    let f = fixture();
    let (filters, layout) = memo_filters(&f.scheme, &[r#"cnt_lower(a) == "abc""#]);
    let mut ctx = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &ctx), vec![true]);
    assert!(ctx.set_field_value_from_name("a", 5i64).is_err());
    assert_eq!(run_all(&filters, &ctx), vec![true]);
    assert_eq!(count(&f.lower), 1);
}

#[test]
fn reset_and_clear_recompute() {
    let f = fixture();
    let (filters, layout) = memo_filters(&f.scheme, &[r#"cnt_lower(a) == "abc""#]);
    let mut ctx = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &ctx), vec![true]);

    ctx.clear();
    set(&mut ctx, "a", "ABC").unwrap();
    set(&mut ctx, "b", "").unwrap();
    assert_eq!(run_all(&filters, &ctx), vec![true]);
    assert_eq!(count(&f.lower), 2);

    let mut ctx = ctx.reset();
    set(&mut ctx, "a", "ABC").unwrap();
    set(&mut ctx, "b", "").unwrap();
    assert_eq!(run_all(&filters, &ctx), vec![true]);
    assert_eq!(count(&f.lower), 3);
    assert_eq!(ctx.memo_layout(), Some(&layout));
}

#[test]
#[should_panic(expected = "mandatory")]
fn clear_alone_drops_cached_results() {
    let f = fixture();
    let (filters, layout) = memo_filters(&f.scheme, &[r#"cnt_lower(a) == "abc""#]);
    let mut ctx = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &ctx), vec![true]);

    // A cleared context has no field `a`: reading it panics. A stale cached
    // result would answer without reading it.
    ctx.clear();
    let _ = filters[0].execute(&ctx);
}

#[test]
fn list_matcher_change_recomputes() {
    let f = fixture();
    let (filters, layout) = memo_filters(&f.scheme, &[r#"cnt_lower(a) == "abc""#]);
    let mut ctx = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &ctx), vec![true]);
    let _ = ctx.get_list_matcher_mut_from_type(&Type::Ip).unwrap();
    assert_eq!(run_all(&filters, &ctx), vec![true]);
    assert_eq!(count(&f.lower), 2);

    let list = f.scheme.get_list(&Type::Ip).unwrap();
    let _ = ctx.get_list_matcher_mut(list);
    assert_eq!(run_all(&filters, &ctx), vec![true]);
    assert_eq!(count(&f.lower), 3);
}

#[test]
fn zero_slot_context_gives_correct_results() {
    let f = fixture();
    let (filters, _layout) = memo_filters(
        &f.scheme,
        &[r#"cnt_lower(a) == "abc""#, r#"cnt_lower(a) == "zzz""#],
    );
    let mut ctx = ExecutionContext::new(&f.scheme);
    set(&mut ctx, "a", "AbC").unwrap();
    set(&mut ctx, "b", "").unwrap();
    assert_eq!(run_all(&filters, &ctx), vec![true, false]);
    assert_eq!(count(&f.lower), 2, "no slots, so no sharing");
    assert_eq!(ctx.memo_layout(), None);
}

#[test]
fn or_stays_lazy() {
    let f = fixture();
    let (filters, layout) = memo_filters(
        &f.scheme,
        &[
            r#"a == "AbC" or cnt_lower(b) == "xyz""#,
            r#"a == "AbC" and cnt_upper(b) == "XYZ""#,
        ],
    );
    let ctx = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &ctx), vec![true, true]);
    assert_eq!(count(&f.lower), 0, "short-circuited");
    assert_eq!(count(&f.upper), 1);
}

#[test]
fn layouts_compare_by_identity() {
    let compiler = MemoCompiler::<()>::new();
    let a = compiler.layout();
    let b = a.clone();
    let other = MemoCompiler::<()>::new().layout();
    assert_eq!(a, b);
    assert_ne!(a, other, "equal contents but a different load");
}

#[test]
fn guard_round_trips_the_memo() {
    let f = fixture();
    let (filters, layout) = memo_filters(&f.scheme, &[r#"cnt_lower(a) == "abc""#]);
    let mut ctx = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &ctx), vec![true]);
    {
        let guard = ctx.borrow_with(());
        assert_eq!(run_all(&filters, &guard), vec![true]);
        assert_eq!(count(&f.lower), 1, "the guard sees the cached slot");
    }
    assert_eq!(run_all(&filters, &ctx), vec![true]);
    assert_eq!(count(&f.lower), 1, "the original gets its memo back");
    assert_eq!(ctx.memo_layout(), Some(&layout));
    // And invalidation still works on the restored table.
    set(&mut ctx, "a", "ABC").unwrap();
    assert_eq!(run_all(&filters, &ctx), vec![true]);
    assert_eq!(count(&f.lower), 2);
}

#[test]
fn guard_invalidation_reaches_the_original() {
    let f = fixture();
    let (filters, layout) = memo_filters(&f.scheme, &[r#"cnt_lower(a) == "abc""#]);
    let mut ctx = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &ctx), vec![true]);
    {
        let mut guard = ctx.borrow_with(());
        set(&mut guard, "a", "OTHER").unwrap();
        assert_eq!(run_all(&filters, &guard), vec![false]);
    }
    assert_eq!(run_all(&filters, &ctx), vec![false]);
    assert_eq!(count(&f.lower), 2);
}

#[test]
fn take_with_and_clone_with_carry_the_memo() {
    let f = fixture();
    let (filters, layout) = memo_filters(&f.scheme, &[r#"cnt_lower(a) == "abc""#]);
    let ctx = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &ctx), vec![true]);

    let cloned = ctx.clone_with(());
    assert_eq!(run_all(&filters, &cloned), vec![true]);
    assert_eq!(count(&f.lower), 1);
    assert_eq!(cloned.memo_layout(), Some(&layout));

    let taken = ctx.take_with(|()| ());
    assert_eq!(run_all(&filters, &taken), vec![true]);
    assert_eq!(count(&f.lower), 1);
    assert_eq!(taken.memo_layout(), Some(&layout));
}

#[test]
fn equality_ignores_the_memo() {
    let f = fixture();
    let (filters, layout) = memo_filters(&f.scheme, &[r#"cnt_lower(a) == "abc""#]);
    let warm = memo_ctx(&f.scheme, &layout);
    let cold = memo_ctx(&f.scheme, &layout);
    assert_eq!(run_all(&filters, &warm), vec![true]);
    assert_eq!(warm, cold);
}

/// Every built-in is evaluated under both compilers and must agree.
#[test]
fn memo_and_default_agree_on_builtin_expressions() {
    use wirefilter::{
        ConcatFunction, EndsWithFunction, LenFunction, RegexReplaceFunction,
        RemoveQueryArgsFunction, StartsWithFunction, SubstringFunction, ToStringFunction,
    };
    let mut b = SchemeBuilder::new();
    b.add_field("a", Type::Bytes).unwrap();
    b.add_field("b", Type::Bytes).unwrap();
    b.add_field("arr", Type::Array(Type::Bytes.into())).unwrap();
    b.add_field("n", Type::Int).unwrap();
    b.add_function("any", AnyFunction::default()).unwrap();
    b.add_function("all", AllFunction::default()).unwrap();
    b.add_function("lower", LowerFunction::default()).unwrap();
    b.add_function("upper", UpperFunction::default()).unwrap();
    b.add_function("url_decode", UrlDecodeFunction::default())
        .unwrap();
    b.add_function("concat", ConcatFunction::default()).unwrap();
    b.add_function("len", LenFunction::default()).unwrap();
    b.add_function("starts_with", StartsWithFunction::default())
        .unwrap();
    b.add_function("ends_with", EndsWithFunction::default())
        .unwrap();
    b.add_function("substring", SubstringFunction::default())
        .unwrap();
    b.add_function("to_string", ToStringFunction::default())
        .unwrap();
    b.add_function("remove_query_args", RemoveQueryArgsFunction::default())
        .unwrap();
    b.add_function("regex_replace", RegexReplaceFunction::default())
        .unwrap();
    let scheme = b.build();
    let exprs = [
        r#"lower(a) == "hello world""#,
        r#"upper(a) == "HELLO WORLD""#,
        r#"lower(url_decode(a, "r")) == "hello world""#,
        r#"upper(url_decode(a, "r")) == "HELLO WORLD""#,
        r#"url_decode(b) contains "x""#,
        r#"len(a) == 11"#,
        r#"len(lower(a)) == 11 and len(upper(a)) == 11"#,
        r#"concat(lower(a), "-", upper(b)) == "hello world-X Y""#,
        r#"starts_with(lower(a), "hello")"#,
        r#"ends_with(lower(a), "world")"#,
        r#"starts_with(lower(a), "nope")"#,
        r#"substring(lower(a), 0, 5) == "hello""#,
        r#"to_string(n) == "7""#,
        r#"lower(to_string(n)) == "7""#,
        r#"remove_query_args(a, "q") == "Hello World""#,
        r#"regex_replace(lower(a), "o", "0") == "hell0 w0rld""#,
        r#"any(lower(arr[*])[*] == "two")"#,
        r#"any(upper(arr[*])[*] == "THREE")"#,
        r#"all(len(arr[*])[*] > 2)"#,
        r#"lower(a) == "hello world" or upper(b) == "nope""#,
        r#"not (lower(a) == "hello world") and upper(b) == "X Y""#,
        r#"lower(url_decode(b, "r")) == "x y" and len(url_decode(b, "r")) == 3"#,
    ];

    let mut memo = MemoCompiler::<()>::new();
    let mut plain = DefaultCompiler::<()>::new();
    let memo_f: Vec<Filter> = exprs
        .iter()
        .map(|e| {
            scheme
                .parse(e)
                .unwrap_or_else(|err| panic!("{e}: {err}"))
                .compile_with_compiler(&mut memo)
        })
        .collect();
    let plain_f: Vec<Filter> = exprs
        .iter()
        .map(|e| scheme.parse(e).unwrap().compile_with_compiler(&mut plain))
        .collect();
    let layout = memo.layout();

    let mut arr = TypedArray::<&str>::new();
    for v in ["ONE", "TWO", "THREE"] {
        arr.push(v);
    }
    let mut ctx = ExecutionContext::new_with_memo(&scheme, &layout);
    ctx.set_field_value(scheme.get_field("a").unwrap(), "Hello World")
        .unwrap();
    ctx.set_field_value(scheme.get_field("b").unwrap(), "X%2520Y")
        .unwrap();
    ctx.set_field_value(scheme.get_field("arr").unwrap(), arr)
        .unwrap();
    ctx.set_field_value(scheme.get_field("n").unwrap(), 7i64)
        .unwrap();

    let expected = run_all(&plain_f, &ctx);
    assert_eq!(run_all(&memo_f, &ctx), expected);
    // Reading the cache again gives the same verdicts.
    assert_eq!(run_all(&memo_f, &ctx), expected);
    assert!(expected.iter().any(|v| *v) && expected.iter().any(|v| !*v));
}

// `Compiler` is used through its trait methods above; keep the import honest.
#[allow(dead_code)]
fn _uses_compiler_trait<C: Compiler>(_: &C) {}
