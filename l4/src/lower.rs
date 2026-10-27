//! Wirefilter AST to [`Formula`].
//!
//! Every comparison becomes a set over one dimension, interned as an atom. A
//! port comparison is additionally guarded by its protocol, so the formula
//! keeps wirefilter's answer for packets on which the field is unset:
//!
//! | wirefilter | formula |
//! |---|---|
//! | `tcp.dst_port == 80` | `tcp and port in {80}` |
//! | `tcp.dst_port != 80`, nil `!=` is `true` | `not tcp or port in {80}ᶜ` |
//! | `tcp.dst_port != 80`, nil `!=` is `false` | `tcp and port in {80}ᶜ` |
//!
//! Anything without an exact set reading is refused: functions, lists,
//! string matching, bitwise tests, field-to-field comparisons, quantifiers and
//! fields outside the [`L4Schema`].

use crate::LowerError;
use crate::formula::{Atom, Formula};
use crate::schema::{L4Field, L4Schema};
use crate::set::{IntervalSet, IpSet, Point};
use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use wirefilter::{
    ComparisonExpr, ComparisonOpExpr, ComparisonRhs, ExplicitIpRange, GetType, IdentifierExpr,
    IpRange, LiteralSet, LiteralValue, LogicalExpr, LogicalOp, OrderingOp, Type, UnaryOp,
};

/// The result of one comparison on a set field: the matching values when the
/// field is set, and the answer when it is not.
struct Match<S> {
    present: S,
    when_unset: bool,
}

/// Walks one expression, interning atoms as it goes.
pub(crate) struct Lowering<'s> {
    schema: &'s L4Schema,
    nil_not_equal: bool,
    atoms: Vec<Atom>,
    index: HashMap<Atom, usize>,
}

impl<'s> Lowering<'s> {
    pub(crate) fn new(schema: &'s L4Schema, nil_not_equal: bool) -> Self {
        Self {
            schema,
            nil_not_equal,
            atoms: Vec::new(),
            index: HashMap::new(),
        }
    }

    pub(crate) fn into_atoms(self) -> Vec<Atom> {
        self.atoms
    }

    pub(crate) fn logical(&mut self, expr: &LogicalExpr) -> Result<Formula, LowerError> {
        match expr {
            LogicalExpr::Combining { op, items } => {
                let items = items
                    .iter()
                    .map(|item| self.logical(item))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(match op {
                    LogicalOp::And => Formula::and(items),
                    LogicalOp::Or => Formula::or(items),
                    LogicalOp::Xor => items
                        .into_iter()
                        .reduce(Formula::xor)
                        .unwrap_or(Formula::Const(false)),
                })
            }
            LogicalExpr::Comparison(comparison) => self.comparison(comparison),
            LogicalExpr::Parenthesized(inner) => self.logical(&inner.expr),
            LogicalExpr::Unary {
                op: UnaryOp::Not,
                arg,
            } => Ok(Formula::not(self.logical(arg)?)),
            LogicalExpr::Quantifier { .. } => Err(unsupported(None, "an any()/all() quantifier")),
        }
    }

    fn comparison(&mut self, comparison: &ComparisonExpr) -> Result<Formula, LowerError> {
        let field = match comparison.lhs.identifier() {
            IdentifierExpr::Field(field) => field,
            IdentifierExpr::FunctionCallExpr(_) => {
                return Err(unsupported(None, "a function call"));
            }
        };
        let name = field.name();
        if !comparison.lhs.indexes().is_empty() {
            return Err(unsupported(Some(name), "an indexed field access"));
        }
        let kind = self
            .schema
            .field(name)
            .ok_or_else(|| LowerError::UnknownField(name.to_owned()))?;
        let expected = expected_type(kind);
        let actual = field.get_type();
        if actual != expected {
            return Err(LowerError::FieldType {
                field: name.to_owned(),
                expected,
                actual,
            });
        }

        if matches!(kind, L4Field::Port { .. }) && !field.optional() {
            return Err(LowerError::MandatoryPortField(name.to_owned()));
        }

        let op = &comparison.op;
        Ok(match *kind {
            L4Field::Ip(side) => {
                let set = self.ip_match(name, op)?.present;
                self.atom(Atom::Ip(side, set))
            }
            L4Field::ProtocolNumber => {
                let set = self.int_match::<u8>(name, op)?.present;
                self.atom(Atom::Protocol(set))
            }
            L4Field::ProtocolName => {
                let set = self.name_match(name, op)?.present;
                self.atom(Atom::Protocol(set))
            }
            L4Field::ProtocolFlag(protocol) => match op {
                ComparisonOpExpr::IsTrue => self.atom(Atom::Protocol(IntervalSet::point(protocol))),
                _ => return Err(unsupported(Some(name), "a non-boolean test of a flag")),
            },
            L4Field::Port { side, protocol } => {
                let Match {
                    present,
                    when_unset,
                } = self.int_match::<u16>(name, op)?;
                let guard = self.atom(Atom::Protocol(IntervalSet::point(protocol.number())));
                let value = if present.is_full() {
                    Formula::Const(true)
                } else {
                    self.atom(Atom::Port(side, present))
                };
                if when_unset {
                    Formula::or([Formula::not(guard), value])
                } else {
                    Formula::and([guard, value])
                }
            }
        })
    }

    /// Interns `atom`, folding the ones every or no packet satisfies.
    ///
    /// Port atoms are never folded to `true`: a full port set still requires
    /// the packet to carry ports. Callers guard them instead.
    fn atom(&mut self, atom: Atom) -> Formula {
        match &atom {
            Atom::Ip(_, set) if set.is_empty() => return Formula::Const(false),
            Atom::Ip(_, set) if set.is_full() => return Formula::Const(true),
            Atom::Protocol(set) if set.is_empty() => return Formula::Const(false),
            Atom::Protocol(set) if set.is_full() => return Formula::Const(true),
            Atom::Port(_, set) if set.is_empty() => return Formula::Const(false),
            _ => {}
        }
        let next = self.atoms.len();
        let index = *self.index.entry(atom.clone()).or_insert(next);
        if index == next {
            self.atoms.push(atom);
        }
        Formula::Var(index)
    }

    fn ordering_rhs<'a>(
        &self,
        field: &str,
        op: &'a ComparisonOpExpr,
    ) -> Result<Option<(OrderingOp, &'a LiteralValue)>, LowerError> {
        match op {
            ComparisonOpExpr::Ordering {
                op,
                rhs: ComparisonRhs::Literal(value),
            } => Ok(Some((*op, value))),
            ComparisonOpExpr::Ordering { .. } => Err(unsupported(
                Some(field),
                "a comparison against another field",
            )),
            ComparisonOpExpr::OneOf(_) => Ok(None),
            other => Err(unsupported(Some(field), op_name(other))),
        }
    }

    /// `!=` is the complement of `==`, plus the scheme's answer for nil.
    fn finish<S>(
        &self,
        op: OrderingOp,
        equal: S,
        ordered: S,
        complement: impl Fn(&S) -> S,
    ) -> Match<S> {
        match op {
            OrderingOp::Equal => Match {
                present: equal,
                when_unset: false,
            },
            OrderingOp::NotEqual => Match {
                present: complement(&equal),
                when_unset: self.nil_not_equal,
            },
            _ => Match {
                present: ordered,
                when_unset: false,
            },
        }
    }

    fn int_match<T>(
        &self,
        field: &str,
        op: &ComparisonOpExpr,
    ) -> Result<Match<IntervalSet<T>>, LowerError>
    where
        T: Point + Into<i64> + TryFrom<i64>,
    {
        match self.ordering_rhs(field, op)? {
            Some((op, LiteralValue::Int(value))) => {
                let value = *value;
                let ordered = match op {
                    OrderingOp::LessThan => {
                        clamp(i64::MIN, value.saturating_sub(1), value == i64::MIN)
                    }
                    OrderingOp::LessThanEqual => clamp(i64::MIN, value, false),
                    OrderingOp::GreaterThan => {
                        clamp(value.saturating_add(1), i64::MAX, value == i64::MAX)
                    }
                    OrderingOp::GreaterThanEqual => clamp(value, i64::MAX, false),
                    OrderingOp::Equal | OrderingOp::NotEqual => IntervalSet::empty(),
                };
                Ok(self.finish(
                    op,
                    clamp(value, value, false),
                    ordered,
                    IntervalSet::complement,
                ))
            }
            Some(_) => Err(unsupported(Some(field), "a non-integer literal")),
            None => match op {
                ComparisonOpExpr::OneOf(LiteralSet::Int(ranges)) => Ok(Match {
                    present: ranges
                        .iter()
                        .map(|range| {
                            let range = RangeInclusive::<i64>::from(range);
                            clamp::<T>(*range.start(), *range.end(), false)
                        })
                        .fold(IntervalSet::empty(), |acc, set| acc.union(&set)),
                    when_unset: false,
                }),
                _ => Err(unsupported(Some(field), "a non-integer set")),
            },
        }
    }

    fn ip_match(&self, field: &str, op: &ComparisonOpExpr) -> Result<Match<IpSet>, LowerError> {
        match self.ordering_rhs(field, op)? {
            Some((op, LiteralValue::Ip(addr))) => {
                let ordered = match op {
                    OrderingOp::LessThan => below(*addr, false),
                    OrderingOp::LessThanEqual => below(*addr, true),
                    OrderingOp::GreaterThan => above(*addr, false),
                    OrderingOp::GreaterThanEqual => above(*addr, true),
                    OrderingOp::Equal | OrderingOp::NotEqual => IpSet::empty(),
                };
                Ok(self.finish(op, ip_point(*addr), ordered, IpSet::complement))
            }
            Some(_) => Err(unsupported(Some(field), "a non-address literal")),
            None => match op {
                ComparisonOpExpr::OneOf(LiteralSet::Ip(ranges)) => Ok(Match {
                    present: ranges
                        .iter()
                        .map(ip_range)
                        .fold(IpSet::empty(), |acc, set| acc.union(&set)),
                    when_unset: false,
                }),
                _ => Err(unsupported(Some(field), "a non-address set")),
            },
        }
    }

    fn name_match(
        &self,
        field: &str,
        op: &ComparisonOpExpr,
    ) -> Result<Match<IntervalSet<u8>>, LowerError> {
        match self.ordering_rhs(field, op)? {
            Some((op @ (OrderingOp::Equal | OrderingOp::NotEqual), LiteralValue::Bytes(name))) => {
                let named = self.schema.protocols_named(name);
                Ok(self.finish(op, named, IntervalSet::empty(), IntervalSet::complement))
            }
            Some(_) => Err(unsupported(Some(field), "an ordering of protocol names")),
            None => match op {
                ComparisonOpExpr::OneOf(LiteralSet::Bytes(names)) => Ok(Match {
                    present: names
                        .iter()
                        .map(|name| self.schema.protocols_named(name))
                        .fold(IntervalSet::empty(), |acc, set| acc.union(&set)),
                    when_unset: false,
                }),
                _ => Err(unsupported(Some(field), "a non-name set")),
            },
        }
    }
}

fn expected_type(field: &L4Field) -> Type {
    match field {
        L4Field::Ip(_) => Type::Ip,
        L4Field::ProtocolNumber | L4Field::Port { .. } => Type::Int,
        L4Field::ProtocolName => Type::Bytes,
        L4Field::ProtocolFlag(_) => Type::Bool,
    }
}

fn unsupported(field: Option<&str>, construct: &'static str) -> LowerError {
    LowerError::Unsupported {
        field: field.map(str::to_owned),
        construct,
    }
}

fn op_name(op: &ComparisonOpExpr) -> &'static str {
    match op {
        ComparisonOpExpr::IsTrue => "a boolean test",
        ComparisonOpExpr::Ordering { .. } | ComparisonOpExpr::OneOf(_) => "a comparison",
        ComparisonOpExpr::Int { .. } => "a bitwise test",
        ComparisonOpExpr::Contains(_) | ComparisonOpExpr::ContainsOneOf(_) => "`contains`",
        ComparisonOpExpr::Matches(_) => "a regex match",
        ComparisonOpExpr::Wildcard(_) | ComparisonOpExpr::StrictWildcard(_) => "a wildcard match",
        ComparisonOpExpr::InList { .. } => "a list lookup",
    }
}

/// `start..=end` restricted to the domain of `T`; empty when `empty` is set
/// or the range misses the domain.
fn clamp<T>(start: i64, end: i64, empty: bool) -> IntervalSet<T>
where
    T: Point + Into<i64> + TryFrom<i64>,
{
    let start = start.max(T::MIN.into());
    let end = end.min(T::MAX.into());
    match (empty, T::try_from(start), T::try_from(end)) {
        (false, Ok(start), Ok(end)) => IntervalSet::range(start, end),
        _ => IntervalSet::empty(),
    }
}

fn ip_point(addr: IpAddr) -> IpSet {
    match addr {
        IpAddr::V4(a) => IpSet::v4_range(a, a),
        IpAddr::V6(a) => IpSet::v6_range(a, a),
    }
}

/// Addresses of `addr`'s family ordered before it (or equal, if `inclusive`).
fn below(addr: IpAddr, inclusive: bool) -> IpSet {
    let mut set = IpSet::empty();
    match addr {
        IpAddr::V4(a) => {
            let end = if inclusive {
                Some(a.to_bits())
            } else {
                a.to_bits().pred()
            };
            if let Some(end) = end {
                set.v4 = IntervalSet::range(0, end);
            }
        }
        IpAddr::V6(a) => {
            let end = if inclusive {
                Some(a.to_bits())
            } else {
                a.to_bits().pred()
            };
            if let Some(end) = end {
                set.v6 = IntervalSet::range(0, end);
            }
        }
    }
    set
}

/// Addresses of `addr`'s family ordered after it (or equal, if `inclusive`).
fn above(addr: IpAddr, inclusive: bool) -> IpSet {
    let mut set = IpSet::empty();
    match addr {
        IpAddr::V4(a) => {
            let start = if inclusive {
                Some(a.to_bits())
            } else {
                a.to_bits().succ()
            };
            if let Some(start) = start {
                set.v4 = IntervalSet::range(start, u32::MAX);
            }
        }
        IpAddr::V6(a) => {
            let start = if inclusive {
                Some(a.to_bits())
            } else {
                a.to_bits().succ()
            };
            if let Some(start) = start {
                set.v6 = IntervalSet::range(start, u128::MAX);
            }
        }
    }
    set
}

fn ip_range(range: &IpRange) -> IpSet {
    match range {
        IpRange::Explicit(ExplicitIpRange::V4(r)) => IpSet::v4_range(*r.start(), *r.end()),
        IpRange::Explicit(ExplicitIpRange::V6(r)) => IpSet::v6_range(*r.start(), *r.end()),
        IpRange::Cidr(cidr) => match (cidr.first_address(), cidr.last_address()) {
            (IpAddr::V4(first), IpAddr::V4(last)) => IpSet::v4_range(first, last),
            (IpAddr::V6(first), IpAddr::V6(last)) => IpSet::v6_range(first, last),
            _ => unreachable!("a CIDR spans one family"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{PortProtocol, Side};
    use wirefilter::SchemeBuilder;

    fn lower(source: &str, nil_not_equal: bool) -> Result<(Formula, Vec<Atom>), LowerError> {
        let mut builder = SchemeBuilder::new();
        for (name, ty) in [
            ("ip.src", Type::Ip),
            ("ip.dst", Type::Ip),
            ("ip.proto", Type::Bytes),
            ("tcp.src_port", Type::Int),
            ("tcp.dst_port", Type::Int),
            ("udp.src_port", Type::Int),
            ("udp.dst_port", Type::Int),
            ("http.host", Type::Bytes),
            ("tcp.dst_ports", Type::Array(Type::Int.into())),
        ] {
            builder.add_optional_field(name, ty).unwrap();
        }
        builder.add_field("mandatory.port", Type::Int).unwrap();
        builder.set_nil_not_equal_behavior(nil_not_equal);
        let scheme = builder.build();
        let ast = scheme.parse(source).expect("test expression parses");
        let schema = L4Schema::amygdala().with_field(
            "mandatory.port",
            L4Field::Port {
                side: Side::Dst,
                protocol: PortProtocol::Tcp,
            },
        );
        let mut lowering = Lowering::new(&schema, scheme.nil_not_equal_behavior());
        let formula = lowering.logical(ast.expression())?;
        Ok((formula, lowering.into_atoms()))
    }

    fn port(start: u16, end: u16) -> Atom {
        Atom::Port(Side::Dst, IntervalSet::range(start, end))
    }

    fn tcp() -> Atom {
        Atom::Protocol(IntervalSet::point(6))
    }

    /// Without the protocol guard, `tcp.dst_port == 80` would also match UDP
    /// packets to port 80.
    #[test]
    fn port_comparison_is_guarded_by_its_protocol() {
        let (formula, atoms) = lower("tcp.dst_port == 80", true).unwrap();
        assert_eq!(atoms, vec![tcp(), port(80, 80)]);
        assert_eq!(formula, Formula::and([Formula::Var(0), Formula::Var(1)]));
    }

    /// With nil `!=` on, `tcp.dst_port != 80` holds for every non-TCP packet;
    /// lowering it as `tcp and port != 80` would narrow the rule.
    #[test]
    fn not_equal_follows_nil_behaviour() {
        let (formula, _) = lower("tcp.dst_port != 80", true).unwrap();
        assert_eq!(
            formula,
            Formula::or([Formula::not(Formula::Var(0)), Formula::Var(1)])
        );
        let (formula, atoms) = lower("tcp.dst_port != 80", false).unwrap();
        assert_eq!(
            atoms[1],
            Atom::Port(Side::Dst, IntervalSet::point(80).complement())
        );
        assert_eq!(formula, Formula::and([Formula::Var(0), Formula::Var(1)]));
    }

    /// A port bound outside 0..=65535 must clamp, not wrap or panic.
    #[test]
    fn integer_bounds_clamp_to_the_port_domain() {
        let (_, atoms) = lower("tcp.dst_port < 1024", true).unwrap();
        assert_eq!(atoms[1], port(0, 1023));
        let (formula, _) = lower("tcp.dst_port > 70000", true).unwrap();
        assert_eq!(formula, Formula::Const(false));
        let (_, atoms) = lower("tcp.dst_port in {1..10 5..20 65530..70000}", true).unwrap();
        assert_eq!(
            atoms[1],
            Atom::Port(
                Side::Dst,
                IntervalSet::from_ranges([(1, 20), (65530, 65535)])
            )
        );
    }

    /// Ordering an address must stay in its own family, as wirefilter does.
    #[test]
    fn address_ordering_stays_in_family() {
        let (_, atoms) = lower("ip.src < 10.0.0.0", true).unwrap();
        let Atom::Ip(Side::Src, set) = &atoms[0] else {
            panic!("expected an address atom");
        };
        assert_eq!(
            set.v4.ranges(),
            &[(0, u32::from_be_bytes([9, 255, 255, 255]))]
        );
        assert!(set.v6.is_empty());

        let (_, atoms) = lower("ip.src != 10.0.0.1", true).unwrap();
        let Atom::Ip(_, set) = &atoms[0] else {
            panic!("expected an address atom");
        };
        assert!(set.v6.is_full());
    }

    /// `icmp` covers two protocol numbers; an unknown name matches nothing.
    #[test]
    fn protocol_names_resolve_through_the_schema() {
        let (_, atoms) = lower(r#"ip.proto == "icmp""#, true).unwrap();
        assert_eq!(
            atoms,
            vec![Atom::Protocol(IntervalSet::from_ranges([(1, 1), (58, 58)]))]
        );
        let (formula, _) = lower(r#"ip.proto == "gre""#, true).unwrap();
        assert_eq!(formula, Formula::Const(false));
    }

    /// The same comparison written twice is one atom, not two independent
    /// variables.
    #[test]
    fn atoms_are_interned() {
        let (_, atoms) = lower(
            "tcp.dst_port == 80 or (tcp.dst_port == 80 and ip.src == 1.1.1.1)",
            true,
        )
        .unwrap();
        assert_eq!(atoms.len(), 3);
    }

    /// Silently skipping a clause would widen the rule.
    #[test]
    fn refuses_what_it_cannot_express() {
        let refused = [
            r#"http.host == "a""#,
            r#"ip.proto contains "tc""#,
            r#"ip.proto matches "^t""#,
            "tcp.dst_port & 1",
            "tcp.dst_port == tcp.src_port",
            "any(tcp.dst_ports[*] == 80)",
            r#"ip.proto > "a""#,
        ];
        for source in refused {
            assert!(lower(source, true).is_err(), "{source} must be refused");
        }
        assert_eq!(
            lower(r#"http.host == "a""#, true).unwrap_err(),
            LowerError::UnknownField("http.host".into())
        );
    }

    /// A mandatory port field is set on every packet, so guarding it with its
    /// protocol would narrow the rule.
    #[test]
    fn refuses_mandatory_port_fields() {
        assert_eq!(
            lower("mandatory.port == 80", true).unwrap_err(),
            LowerError::MandatoryPortField("mandatory.port".into())
        );
    }
}
