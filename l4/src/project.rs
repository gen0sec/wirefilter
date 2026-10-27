//! A minimised cube back to sets, one per dimension.
//!
//! A cube's literals on one dimension intersect: `port in A and not port in
//! B` is the port set `A \ B`. Ports need care, because a port atom is false
//! on a packet without ports: a positive port literal excludes every portless
//! protocol, a negative one is vacuously true there. So a cube splits into a
//! TCP/UDP term carrying the port sets and a portless term carrying none, and
//! the two merge back when the ports are unconstrained.

use crate::formula::{Atom, ported_protocols};
use crate::schema::Side;
use crate::set::{IntervalSet, IpSet};

/// The packets one cube matches, as one set per dimension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Term {
    pub protocols: IntervalSet<u8>,
    pub src_ip: IpSet,
    pub dst_ip: IpSet,
    /// Full unless every protocol in `protocols` carries ports.
    pub src_port: IntervalSet<u16>,
    /// Full unless every protocol in `protocols` carries ports.
    pub dst_port: IntervalSet<u16>,
}

pub(crate) fn project(atoms: &[Atom], cube: &[Option<bool>]) -> Vec<Term> {
    let mut protocols = IntervalSet::full();
    let mut src_ip = IpSet::full();
    let mut dst_ip = IpSet::full();
    let mut src_port = IntervalSet::full();
    let mut dst_port = IntervalSet::full();
    let mut requires_ports = false;

    for (atom, literal) in atoms.iter().zip(cube) {
        let Some(positive) = *literal else {
            continue;
        };
        match atom {
            Atom::Ip(side, set) => {
                let set = if positive {
                    set.clone()
                } else {
                    set.complement()
                };
                let target = match side {
                    Side::Src => &mut src_ip,
                    Side::Dst => &mut dst_ip,
                };
                *target = target.intersection(&set);
            }
            Atom::Protocol(set) => {
                let set = if positive {
                    set.clone()
                } else {
                    set.complement()
                };
                protocols = protocols.intersection(&set);
            }
            Atom::Port(side, set) => {
                requires_ports |= positive;
                let set = if positive {
                    set.clone()
                } else {
                    set.complement()
                };
                let target = match side {
                    Side::Src => &mut src_port,
                    Side::Dst => &mut dst_port,
                };
                *target = target.intersection(&set);
            }
        }
    }

    if protocols.is_empty() || src_ip.is_empty() || dst_ip.is_empty() {
        return Vec::new();
    }

    let term = |protocols, src_port, dst_port| Term {
        protocols,
        src_ip: src_ip.clone(),
        dst_ip: dst_ip.clone(),
        src_port,
        dst_port,
    };

    if !requires_ports && src_port.is_full() && dst_port.is_full() {
        return vec![term(protocols, src_port, dst_port)];
    }

    let ported = ported_protocols();
    let mut terms = Vec::with_capacity(2);
    let with_ports = protocols.intersection(&ported);
    if !with_ports.is_empty() && !src_port.is_empty() && !dst_port.is_empty() {
        terms.push(term(with_ports, src_port, dst_port));
    }
    let portless = protocols.difference(&ported);
    if !requires_ports && !portless.is_empty() {
        terms.push(term(portless, IntervalSet::full(), IntervalSet::full()));
    }
    terms
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port(start: u16, end: u16) -> Atom {
        Atom::Port(Side::Dst, IntervalSet::range(start, end))
    }

    /// `not port 80` alone still matches ICMP: dropping the portless term
    /// would narrow the rule.
    #[test]
    fn negative_port_literal_keeps_portless_protocols() {
        let terms = project(&[port(80, 80)], &[Some(false)]);
        assert_eq!(terms.len(), 2);
        assert_eq!(terms[0].protocols, ported_protocols());
        assert_eq!(terms[0].dst_port, IntervalSet::point(80).complement());
        assert_eq!(terms[1].protocols, ported_protocols().complement());
        assert!(terms[1].dst_port.is_full());
    }

    /// `port 80` cannot hold on a portless packet: keeping a portless term
    /// would widen the rule to all ICMP.
    #[test]
    fn positive_port_literal_drops_portless_protocols() {
        let terms = project(&[port(80, 80)], &[Some(true)]);
        assert_eq!(terms.len(), 1);
        assert_eq!(terms[0].protocols, ported_protocols());
    }

    /// Contradictory literals on one dimension make the cube match nothing.
    #[test]
    fn empty_intersection_drops_the_cube() {
        let terms = project(&[port(80, 80), port(443, 443)], &[Some(true), Some(true)]);
        assert!(terms.is_empty());
    }

    /// A cube without port literals stays one term over every protocol.
    #[test]
    fn unconstrained_ports_stay_one_term() {
        let atoms = [Atom::Protocol(IntervalSet::point(6))];
        let terms = project(&atoms, &[Some(false)]);
        assert_eq!(terms.len(), 1);
        assert_eq!(terms[0].protocols, IntervalSet::point(6).complement());
    }
}
