//! Lowers wirefilter expressions into Hillock L4 (5-tuple) firewall rules.
//!
//! [`lower`] turns a parsed [`FilterAst`] into Hillock [`FirewallRule`]s over
//! address family, source/destination prefix, source/destination port range
//! and protocol, such that a packet matches the expression exactly when it
//! matches one of the rules. Every rule carries the caller's action; the
//! ruleset around them (id, name, direction, priority) stays the caller's.
//! IPv4 and IPv6 rules come out together, which one ruleset holds on every
//! backend but iptables.
//!
//! ```ignore
//! let rules = wirefilter_l4::lower(&ast, &L4Schema::amygdala(), FilterAction::Block)?;
//! let ruleset = Ruleset::new(id, name, NetworkDirection::Ingress, priority).with_rules(rules);
//! ```
//!
//! [`check`] tells whether an expression lowers at all, and why not when it
//! does not, so a caller can route it to the firewall or keep it in the
//! wirefilter engine.
//!
//! ```text
//! FilterAst ─► Formula over atoms ─► BDD ─► Espresso ─► cubes ─► sets ─► rules
//!              (lower)                      (minimize)  (project)  (rules)
//! ```
//!
//! 1. **Lower.** Each comparison becomes an atom, a set over one dimension
//!    (`tcp.dst_port in {80 443}` is the port set `{80, 443}`); the logical
//!    structure becomes a boolean formula over atom indices.
//!    The [`L4Schema`] names the fields and how they are spelled.
//! 2. **Minimise.** Espresso turns the formula into a small sum of products,
//!    with impossible atom combinations (`port 80 and port 443`) as
//!    don't-cares.
//! 3. **Project.** Each product term intersects its literals per dimension.
//! 4. **Expand.** Each set becomes prefixes, port ranges and protocols; their
//!    cross product is the term's rules. An address-less rule gets a `/0`
//!    source, so every backend keeps it to its family.
//!
//! # Refuse rather than widen
//!
//! A clause the rules cannot express exactly is an error, never dropped:
//! dropping it would install a rule matching more than was written. That
//! covers unknown fields, functions, lists, string matching, bitwise tests,
//! quantifiers, protocols Hillock has no name for (anything but TCP, UDP,
//! ICMP and ICMPv6), and an expression whose rules exceed [`Limits`].
//!
//! The one known narrowing is ICMP across families: protocol 1 is emitted only
//! under IPv4 and protocol 58 only under IPv6. An IPv6 packet whose next
//! header is 1 is not ICMP to any stack, and Hillock's nftables backend
//! refuses the pairing.
//!
//! # Unset fields
//!
//! Wirefilter evaluates a comparison against an unset field as `false`, and
//! `!=` as the scheme's
//! [`nil_not_equal_behavior`](wirefilter::Scheme::nil_not_equal_behavior).
//! Port fields are unset on packets of other protocols, so the lowering guards
//! them with their protocol; see [`L4Field::Port`].

mod formula;
mod lower;
mod minimize;
mod project;
mod rules;
mod schema;
mod set;

use hillock::common::FirewallRule;
use hillock::common::firewall_rules::FreshRuleId;
pub use schema::{L4Field, L4Schema, PortProtocol, Side};
use thiserror::Error;
use wirefilter::{FilterAst, Type};

/// Why an expression has no exact L4 lowering.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LowerError {
    /// The expression uses a field the [`L4Schema`] does not name.
    #[error("field `{0}` is not an L4 field")]
    UnknownField(String),

    /// A field's scheme type differs from what its [`L4Field`] requires.
    #[error("field `{field}` is {actual:?}, but the L4 schema expects {expected:?}")]
    FieldType {
        /// The field.
        field: String,
        /// The type the [`L4Field`] requires.
        expected: Type,
        /// The type in the wirefilter scheme.
        actual: Type,
    },

    /// A port field is mandatory, so the scheme cannot leave it unset on
    /// packets of other protocols, which the protocol guard relies on.
    #[error("port field `{0}` must be optional: it is unset on packets of other protocols")]
    MandatoryPortField(String),

    /// The expression uses a construct with no set reading.
    #[error("{construct}{} cannot be lowered to L4 rules", .field.as_ref().map(|f| format!(" on `{f}`")).unwrap_or_default())]
    Unsupported {
        /// The field it applies to, if any.
        field: Option<String>,
        /// What was refused.
        construct: &'static str,
    },

    /// The expression matches a protocol a rule cannot name.
    #[error("protocol {0} cannot be named in an L4 rule")]
    UnrepresentableProtocol(u8),

    /// The expression has more distinct comparisons than [`Limits::max_atoms`].
    #[error("expression has {count} distinct comparisons, more than the limit of {limit}")]
    TooManyAtoms {
        /// Distinct comparisons in the expression.
        count: usize,
        /// The limit.
        limit: usize,
    },

    /// The expression lowers to more rules than [`Limits::max_rules`].
    #[error("expression lowers to more than {limit} rules")]
    TooManyRules {
        /// The limit.
        limit: usize,
    },

    /// Espresso failed.
    #[error("minimisation failed: {0}")]
    Minimization(String),
}

/// Bounds on the work one expression may cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Distinct comparisons (atoms). Minimisation cost grows exponentially
    /// with this in the worst case.
    pub max_atoms: usize,
    /// Rules in the result. Negated address sets are the usual cause of many
    /// rules: `not ip.src in {10.0.0.0/8}` alone is a dozen prefixes per
    /// family.
    pub max_rules: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_atoms: 64,
            max_rules: 4096,
        }
    }
}

/// Lowers `ast` with the default [`Limits`].
pub fn lower<T, TID, A>(
    ast: &FilterAst,
    schema: &L4Schema,
    action: A,
) -> Result<Vec<FirewallRule<T, TID, A>>, LowerError>
where
    T: Default,
    TID: FreshRuleId,
    A: Clone,
{
    lower_with_limits(ast, schema, action, Limits::default())
}

/// Lowers `ast` into rules, each with `action`, matching exactly the packets
/// it matches. An empty result matches no packet.
///
/// The rules may overlap and carry no order: every one has priority 0 and a
/// fresh id.
pub fn lower_with_limits<T, TID, A>(
    ast: &FilterAst,
    schema: &L4Schema,
    action: A,
    limits: Limits,
) -> Result<Vec<FirewallRule<T, TID, A>>, LowerError>
where
    T: Default,
    TID: FreshRuleId,
    A: Clone,
{
    let mut lowering = lower::Lowering::new(schema, ast.scheme().nil_not_equal_behavior());
    let formula = lowering.logical(ast.expression())?;
    let atoms = lowering.into_atoms();
    if atoms.len() > limits.max_atoms {
        return Err(LowerError::TooManyAtoms {
            count: atoms.len(),
            limit: limits.max_atoms,
        });
    }

    let exclusions = formula::exclusions(&atoms);
    let cubes = minimize::minimize(&formula, &exclusions, atoms.len())?;

    let mut sink = rules::RuleSink::new(action, limits.max_rules);
    for cube in &cubes {
        for term in project::project(&atoms, cube) {
            sink.expand(&term)?;
        }
    }
    Ok(sink.into_rules())
}

/// Whether `ast` lowers with the default [`Limits`]: `Ok(())` exactly when
/// [`lower`] succeeds, otherwise the error it would return.
///
/// Use it to route an expression: one that passes can go to the firewall,
/// one that does not stays with the wirefilter engine.
pub fn check(ast: &FilterAst, schema: &L4Schema) -> Result<(), LowerError> {
    check_with_limits(ast, schema, Limits::default())
}

/// Whether `ast` lowers within `limits`: `Ok(())` exactly when
/// [`lower_with_limits`] succeeds, otherwise the error it would return.
pub fn check_with_limits(
    ast: &FilterAst,
    schema: &L4Schema,
    limits: Limits,
) -> Result<(), LowerError> {
    // The same pipeline, so the answer cannot drift from `lower`'s; only the
    // ids are skipped.
    #[derive(Default)]
    struct NoId;
    impl FreshRuleId for NoId {}

    lower_with_limits::<(), NoId, ()>(ast, schema, (), limits).map(drop)
}
