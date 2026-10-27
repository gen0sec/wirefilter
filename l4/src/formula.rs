//! Boolean structure over atoms, and the atoms themselves.
//!
//! An [`Atom`] is one set over one packet dimension; a [`Formula`] combines
//! atom indices with `and`/`or`/`xor`/`not`. Espresso sees only the formula,
//! as if every atom were an independent variable. They are not: `port is 80`
//! and `port is 443` cannot both hold. [`exclusions`] spells out those
//! impossible combinations so the minimiser may use them as don't-cares; the
//! projection back to rules re-derives every set exactly, so a missed
//! exclusion costs only a less compact result, never a wrong one.

use crate::schema::{PROTO_TCP, PROTO_UDP, Side};
use crate::set::{IntervalSet, IpSet};

/// Protocols whose packets carry ports.
pub(crate) fn ported_protocols() -> IntervalSet<u8> {
    IntervalSet::point(PROTO_TCP).union(&IntervalSet::point(PROTO_UDP))
}

/// One predicate over one packet dimension.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Atom {
    /// The address on `Side` is in the set.
    Ip(Side, IpSet),
    /// The protocol number is in the set.
    Protocol(IntervalSet<u8>),
    /// The packet carries ports (it is TCP or UDP) and the port on `Side` is
    /// in the set.
    Port(Side, IntervalSet<u16>),
}

/// A boolean combination of atoms, by index.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Formula {
    Const(bool),
    Var(usize),
    Not(Box<Formula>),
    And(Vec<Formula>),
    Or(Vec<Formula>),
    Xor(Box<Formula>, Box<Formula>),
}

impl Formula {
    pub(crate) fn not(f: Formula) -> Formula {
        match f {
            Formula::Const(v) => Formula::Const(!v),
            Formula::Not(inner) => *inner,
            f => Formula::Not(Box::new(f)),
        }
    }

    pub(crate) fn and(items: impl IntoIterator<Item = Formula>) -> Formula {
        Self::fold(items, false)
    }

    pub(crate) fn or(items: impl IntoIterator<Item = Formula>) -> Formula {
        Self::fold(items, true)
    }

    /// `and` (absorbing `false`) or `or` (absorbing `true`), flattened and
    /// with constants folded.
    fn fold(items: impl IntoIterator<Item = Formula>, absorbing: bool) -> Formula {
        let mut out = Vec::new();
        for item in items {
            match item {
                Formula::Const(v) if v == absorbing => return Formula::Const(absorbing),
                Formula::Const(_) => {}
                Formula::And(inner) if !absorbing => out.extend(inner),
                Formula::Or(inner) if absorbing => out.extend(inner),
                f => out.push(f),
            }
        }
        match out.len() {
            0 => Formula::Const(!absorbing),
            1 => out.pop().unwrap(),
            _ if absorbing => Formula::Or(out),
            _ => Formula::And(out),
        }
    }

    pub(crate) fn xor(a: Formula, b: Formula) -> Formula {
        match (a, b) {
            (Formula::Const(x), Formula::Const(y)) => Formula::Const(x != y),
            (Formula::Const(false), f) | (f, Formula::Const(false)) => f,
            (Formula::Const(true), f) | (f, Formula::Const(true)) => Formula::not(f),
            (a, b) => Formula::Xor(Box::new(a), Box::new(b)),
        }
    }

    /// Evaluates the formula with atom `i` set to `assignment[i]`.
    #[cfg(test)]
    pub(crate) fn eval(&self, assignment: &[bool]) -> bool {
        match self {
            Formula::Const(v) => *v,
            Formula::Var(i) => assignment[*i],
            Formula::Not(f) => !f.eval(assignment),
            Formula::And(fs) => fs.iter().all(|f| f.eval(assignment)),
            Formula::Or(fs) => fs.iter().any(|f| f.eval(assignment)),
            Formula::Xor(a, b) => a.eval(assignment) != b.eval(assignment),
        }
    }
}

/// The disjunction of every atom combination no packet can produce.
///
/// Only pairs are examined. Larger impossible combinations (three port atoms
/// that together cover the domain) are left out, which is sound.
pub(crate) fn exclusions(atoms: &[Atom]) -> Formula {
    let var = Formula::Var;
    let not = |i| Formula::not(Formula::Var(i));
    let ported = ported_protocols();

    let mut out = Vec::new();
    for (i, a) in atoms.iter().enumerate() {
        for (j, b) in atoms.iter().enumerate().skip(i + 1) {
            match relation(a, b, &ported) {
                Relation::None => {}
                Relation::Disjoint => out.push(Formula::and([var(i), var(j)])),
                Relation::Subset => out.push(Formula::and([var(i), not(j)])),
                Relation::Superset => out.push(Formula::and([var(j), not(i)])),
            }
        }
    }
    Formula::or(out)
}

enum Relation {
    None,
    /// Both cannot hold.
    Disjoint,
    /// The first implies the second.
    Subset,
    /// The second implies the first.
    Superset,
}

fn relation(a: &Atom, b: &Atom, ported: &IntervalSet<u8>) -> Relation {
    fn sets<S>(
        a: &S,
        b: &S,
        disjoint: impl Fn(&S, &S) -> bool,
        subset: impl Fn(&S, &S) -> bool,
    ) -> Relation {
        if disjoint(a, b) {
            Relation::Disjoint
        } else if subset(a, b) {
            Relation::Subset
        } else if subset(b, a) {
            Relation::Superset
        } else {
            Relation::None
        }
    }

    match (a, b) {
        (Atom::Ip(sa, a), Atom::Ip(sb, b)) if sa == sb => {
            sets(a, b, IpSet::is_disjoint, IpSet::is_subset)
        }
        (Atom::Protocol(a), Atom::Protocol(b)) => {
            sets(a, b, IntervalSet::is_disjoint, IntervalSet::is_subset)
        }
        (Atom::Port(sa, a), Atom::Port(sb, b)) if sa == sb => {
            sets(a, b, IntervalSet::is_disjoint, IntervalSet::is_subset)
        }
        // A port atom implies the protocol carries ports.
        (Atom::Port(..), Atom::Protocol(p)) if p.is_disjoint(ported) => Relation::Disjoint,
        (Atom::Port(..), Atom::Protocol(p)) if ported.is_subset(p) => Relation::Subset,
        (Atom::Protocol(p), Atom::Port(..)) if p.is_disjoint(ported) => Relation::Disjoint,
        (Atom::Protocol(p), Atom::Port(..)) if ported.is_subset(p) => Relation::Superset,
        _ => Relation::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constant folding that kept `x and false` alive would hand the minimiser
    /// a cube no packet satisfies.
    #[test]
    fn folds_constants() {
        let x = Formula::Var(0);
        assert_eq!(
            Formula::and([x.clone(), Formula::Const(false)]),
            Formula::Const(false)
        );
        assert_eq!(Formula::or([x.clone(), Formula::Const(false)]), x);
        assert_eq!(
            Formula::xor(x.clone(), Formula::Const(true)),
            Formula::not(x.clone())
        );
        assert_eq!(Formula::not(Formula::not(x.clone())), x);
        assert_eq!(Formula::and([]), Formula::Const(true));
        assert_eq!(Formula::or([]), Formula::Const(false));
    }

    /// An exclusion that is not actually impossible would let the minimiser
    /// drop a literal some packet depends on.
    #[test]
    fn exclusions_are_sound() {
        let port = |s, e| Atom::Port(Side::Dst, IntervalSet::range(s, e));
        let atoms = vec![
            port(80, 80),
            port(443, 443),
            port(1, 1024),
            Atom::Protocol(IntervalSet::point(1)),
            Atom::Port(Side::Src, IntervalSet::point(80)),
        ];
        let dc = exclusions(&atoms);

        // 80 and 443 at once: impossible.
        assert!(dc.eval(&[true, true, false, false, false]));
        // 80 outside 1..=1024: impossible.
        assert!(dc.eval(&[true, false, false, false, false]));
        // A port on an ICMP packet: impossible.
        assert!(dc.eval(&[false, false, true, true, false]));
        // Port 80 (within 1..=1024), and source port 80: possible.
        assert!(!dc.eval(&[true, false, true, false, true]));
    }
}
