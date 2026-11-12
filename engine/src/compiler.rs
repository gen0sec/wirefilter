use crate::scheme::{Field, Function};
use crate::{
    ComparisonExpr, CompiledExpr, CompiledValueExpr, Expr, FunctionCallArgExpr, FunctionCallExpr,
    IndexExpr, LogicalExpr, ValueExpr, Visitor,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Trait used to drive the compilation of a [`crate::FilterAst`] into a [`crate::Filter`].
pub trait Compiler: Sized {
    /// The user data type passed in the  [`crate::ExecutionContext`].
    type U: 'static;

    /// Compiles a [`Expr`] node into a [`CompiledExpr`] (boxed closure).
    #[inline]
    fn compile_expr(&mut self, node: impl Expr) -> CompiledExpr<Self::U> {
        node.compile_with_compiler(self)
    }

    /// Compiles a [`LogicalExpr`] node into a [`CompiledExpr`] (boxed closure).
    #[inline]
    fn compile_logical_expr(&mut self, node: LogicalExpr) -> CompiledExpr<Self::U> {
        self.compile_expr(node)
    }

    /// Compiles a [`ComparisonExpr`] node into a [`CompiledExpr`] (boxed closure).
    #[inline]
    fn compile_comparison_expr(&mut self, node: ComparisonExpr) -> CompiledExpr<Self::U> {
        self.compile_expr(node)
    }

    /// Compiles a [`ValueExpr`] node into a [`CompiledValueExpr`] (boxed closure).
    #[inline]
    fn compile_value_expr(&mut self, node: impl ValueExpr) -> CompiledValueExpr<Self::U> {
        node.compile_with_compiler(self)
    }

    /// Compiles a [`FunctionCallExpr`] node into a [`CompiledValueExpr`] (boxed closure).
    #[inline]
    fn compile_function_call_expr(&mut self, node: FunctionCallExpr) -> CompiledValueExpr<Self::U> {
        self.compile_value_expr(node)
    }

    /// Compiles a [`FunctionCallArgExpr`] node into a [`CompiledValueExpr`] (boxed closure).
    #[inline]
    fn compile_function_call_arg_expr(
        &mut self,
        node: FunctionCallArgExpr,
    ) -> CompiledValueExpr<Self::U> {
        self.compile_value_expr(node)
    }

    /// Compiles a [`IndexExpr`] node into a [`CompiledValueExpr`] (boxed closure).
    #[inline]
    fn compile_index_expr(&mut self, node: IndexExpr) -> CompiledValueExpr<Self::U> {
        self.compile_value_expr(node)
    }
}

/// Default compiler
#[derive(Clone, Copy, Debug)]
pub struct DefaultCompiler<U = ()> {
    _marker: std::marker::PhantomData<U>,
}

impl<U> Default for DefaultCompiler<U> {
    #[inline]
    fn default() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<U> DefaultCompiler<U> {
    /// Creates a new [`DefaultCompiler`].
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<U: 'static> Compiler for DefaultCompiler<U> {
    type U = U;
}

/// Shape of the memo table that a [`MemoCompiler`] expects from an
/// [`crate::ExecutionContext`].
///
/// Create the context with [`crate::ExecutionContext::new_with_memo`]. Two
/// layouts compare equal only when they are the same object, so a layout that
/// is rebuilt on every configuration load tells a caller holding a recycled
/// context that the context no longer fits the compiled filters.
#[derive(Clone, Debug)]
pub struct MemoLayout(Arc<MemoLayoutInner>);

#[derive(Debug)]
struct MemoLayoutInner {
    slot_count: usize,
    /// For each field index, the slots whose call reads that field. A field
    /// past the end of the table feeds no slot.
    dependents: Box<[Box<[usize]>]>,
    /// Identity of the [`MemoCompiler`] that created the layout.
    owner: Arc<()>,
}

impl MemoLayout {
    /// Number of memoized function calls.
    #[inline]
    pub fn slot_count(&self) -> usize {
        self.0.slot_count
    }

    /// Slots that read the field at `index`.
    #[inline]
    pub(crate) fn dependents(&self, index: usize) -> &[usize] {
        self.0.dependents.get(index).map_or(&[], |d| d)
    }

    #[inline]
    pub(crate) fn owner(&self) -> &Arc<()> {
        &self.0.owner
    }
}

impl PartialEq for MemoLayout {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for MemoLayout {}

/// Finds out whether every function inside a call is pure.
struct PurityVisitor {
    pure: bool,
}

impl<'a> Visitor<'a> for PurityVisitor {
    #[inline]
    fn visit_function(&mut self, function: &'a Function) {
        self.pure &= function.as_definition().is_pure();
    }
}

/// Collects the fields that a call reads, through every argument.
struct FieldVisitor {
    fields: Vec<usize>,
}

impl<'a> Visitor<'a> for FieldVisitor {
    #[inline]
    fn visit_field(&mut self, field: &'a Field) {
        self.fields.push(field.index());
    }
}

/// Compiler that computes each pure function call once per
/// [`crate::ExecutionContext`].
///
/// One compiler hands out one slot per distinct [`FunctionCallExpr`], so
/// every [`crate::Filter`] compiled with the same compiler shares the result.
/// A call is memoized only when no function inside it is impure, see
/// [`crate::FunctionDefinition::is_pure`].
///
/// Execute the filters against a context from
/// [`crate::ExecutionContext::new_with_memo`] and the layout from
/// [`MemoCompiler::layout`]. A context uses its slots only for filters of the
/// compiler that created its layout, whichever layout of that compiler it was
/// built from. Against any other context every call is computed as usual.
///
/// Setting a field drops only the results of the calls that read it, through
/// any argument. Clearing the context or changing a list drops all of them.
#[derive(Debug)]
pub struct MemoCompiler<U = ()> {
    owner: Arc<()>,
    slots: HashMap<FunctionCallExpr, usize>,
    /// Indexes of the fields read by each slot's call, sorted and unique.
    slot_fields: Vec<Box<[usize]>>,
    _marker: std::marker::PhantomData<fn() -> U>,
}

impl<U> Default for MemoCompiler<U> {
    #[inline]
    fn default() -> Self {
        Self {
            owner: Arc::new(()),
            slots: HashMap::new(),
            slot_fields: Vec::new(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<U> MemoCompiler<U> {
    /// Creates a new [`MemoCompiler`].
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the layout of the contexts that suit the filters compiled so far.
    ///
    /// Every call returns a new, unequal layout: call it once, after the last
    /// filter is compiled, and clone the result.
    pub fn layout(&self) -> MemoLayout {
        let field_count = self
            .slot_fields
            .iter()
            .flat_map(|fields| fields.last())
            .max()
            .map_or(0, |max| max + 1);
        let mut dependents = vec![Vec::new(); field_count];
        for (slot, fields) in self.slot_fields.iter().enumerate() {
            for &field in fields.iter() {
                dependents[field].push(slot);
            }
        }
        MemoLayout(Arc::new(MemoLayoutInner {
            slot_count: self.slots.len(),
            dependents: dependents.into_iter().map(Vec::into_boxed_slice).collect(),
            owner: self.owner.clone(),
        }))
    }
}

impl<U: 'static> Compiler for MemoCompiler<U> {
    type U = U;

    fn compile_function_call_expr(&mut self, node: FunctionCallExpr) -> CompiledValueExpr<U> {
        let mut purity = PurityVisitor { pure: true };
        node.walk(&mut purity);
        if !purity.pure {
            return self.compile_value_expr(node);
        }
        let next = self.slots.len();
        let slot = *self.slots.entry(node.clone()).or_insert(next);
        if slot == next {
            let mut reads = FieldVisitor { fields: Vec::new() };
            node.walk(&mut reads);
            reads.fields.sort_unstable();
            reads.fields.dedup();
            self.slot_fields.push(reads.fields.into());
        }
        let call = self.compile_value_expr(node);
        let owner = self.owner.clone();
        CompiledValueExpr::new(move |ctx| ctx.memoize(&owner, slot, || call.execute(ctx)))
    }
}
