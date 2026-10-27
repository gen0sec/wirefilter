//! The output: Hillock [`FirewallRule`]s.
//!
//! A rule matches one address family, at most one prefix per side, at most
//! one port range per side and at most one protocol. A [`Term`] holds
//! arbitrary sets, so it expands to the cross product of its prefixes, port
//! ranges and protocols.
//!
//! Every rule gets the caller's action, a fresh id and priority 0: the rules
//! carry no order, so a tie is exactly what they mean.
//!
//! # The family travels in an address
//!
//! A rule without addresses still matches one family only. The eBPF datapaths
//! read the family from `ip_version`, but nftables, DOCA and WFP read it from
//! the addresses (or an ICMP protocol) and install an address-less rule for
//! both families, which would widen `ip.src >= 0.0.0.0` to every IPv6 packet.
//! So an address-less rule gets a `/0` source in its own family, which every
//! backend reads as "any address of this family" (Hillock's
//! `docs/firewall_rule_lowering.md` §9).
//!
//! iptables takes the family from the ruleset (`IpTablesRulesetExt`) instead,
//! so there each family needs its own ruleset.
//!
//! # ICMP and the address family
//!
//! Protocol 1 is emitted only under IPv4 and protocol 58 only under IPv6. An
//! IPv6 packet whose next header is 1 is not ICMP to any stack, and Hillock's
//! nftables backend refuses the pairing (`validate_ip_version`). This is the
//! one place the rules match less than the expression.

use crate::LowerError;
use crate::project::Term;
use crate::schema::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use crate::set::{IntervalSet, IpSet, range_to_prefixes};
use hillock::common::firewall_rules::FreshRuleId;
use hillock::common::{FirewallRule, IPProtocol, IpRange, IpVersion, PortRange};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The fields that make two rules the same match. `FirewallRule` is not
/// `Hash`, and its ids always differ.
type MatchKey = (
    IpVersion,
    Option<IpRange>,
    Option<IpRange>,
    Option<PortRange>,
    Option<PortRange>,
    Option<u8>,
);

/// Collects rules in first-seen order, skipping exact duplicates.
pub(crate) struct RuleSink<T, TID, A> {
    action: A,
    max_rules: usize,
    rules: Vec<FirewallRule<T, TID, A>>,
    seen: HashSet<MatchKey>,
}

impl<T: Default, TID: FreshRuleId, A: Clone> RuleSink<T, TID, A> {
    pub(crate) fn new(action: A, max_rules: usize) -> Self {
        Self {
            action,
            max_rules,
            rules: Vec::new(),
            seen: HashSet::new(),
        }
    }

    pub(crate) fn into_rules(self) -> Vec<FirewallRule<T, TID, A>> {
        self.rules
    }

    /// Appends `term`'s rules.
    pub(crate) fn expand(&mut self, term: &Term) -> Result<(), LowerError> {
        for ip_version in [IpVersion::V4, IpVersion::V6] {
            let src_ips = prefixes(&term.src_ip, ip_version);
            let dst_ips = prefixes(&term.dst_ip, ip_version);
            let protocols = protocols(&term.protocols, ip_version)?;
            let src_ports = ports(&term.src_port);
            let dst_ports = ports(&term.dst_port);

            for &src_ip in &src_ips {
                for &dst_ip in &dst_ips {
                    let src_ip = match (src_ip, dst_ip) {
                        (None, None) => Some(any_address(ip_version)),
                        _ => src_ip,
                    };
                    for &protocol in &protocols {
                        for &src_port in &src_ports {
                            for &dst_port in &dst_ports {
                                self.push(FirewallRule {
                                    rule_id: TID::fresh_rule_id(),
                                    priority: 0,
                                    ip_version,
                                    src_ip,
                                    dst_ip,
                                    src_port,
                                    dst_port,
                                    protocol,
                                    tcp_flags: None,
                                    icmp: None,
                                    ct_state: None,
                                    action: self.action.clone(),
                                    ttl: None,
                                    ext: T::default(),
                                })?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn push(&mut self, rule: FirewallRule<T, TID, A>) -> Result<(), LowerError> {
        let key = (
            rule.ip_version,
            rule.src_ip,
            rule.dst_ip,
            rule.src_port,
            rule.dst_port,
            rule.protocol.map(|protocol| protocol as u8),
        );
        if self.seen.contains(&key) {
            return Ok(());
        }
        if self.rules.len() == self.max_rules {
            return Err(LowerError::TooManyRules {
                limit: self.max_rules,
            });
        }
        self.seen.insert(key);
        self.rules.push(rule);
        Ok(())
    }
}

fn any_address(ip_version: IpVersion) -> IpRange {
    match ip_version {
        IpVersion::V4 => IpRange::ANY_V4,
        IpVersion::V6 => IpRange::ANY_V6,
    }
}

/// The prefixes covering `set`'s addresses in `ip_version`: `[None]` for the
/// whole family, empty when the set holds no address of it.
fn prefixes(set: &IpSet, ip_version: IpVersion) -> Vec<Option<IpRange>> {
    let (ranges, full, bits): (Vec<(u128, u128)>, bool, u32) = match ip_version {
        IpVersion::V4 => (
            set.v4
                .ranges()
                .iter()
                .map(|&(s, e)| (s.into(), e.into()))
                .collect(),
            set.v4.is_full(),
            32,
        ),
        IpVersion::V6 => (set.v6.ranges().to_vec(), set.v6.is_full(), 128),
    };
    if full {
        return vec![None];
    }
    ranges
        .into_iter()
        .flat_map(|(start, end)| range_to_prefixes(start, end, bits))
        .map(|(network, len)| {
            let len = u32::from(len);
            Some(match ip_version {
                IpVersion::V4 => IpRange::V4(Ipv4Addr::from_bits(network as u32), len),
                IpVersion::V6 => IpRange::V6(Ipv6Addr::from_bits(network), len),
            })
        })
        .collect()
}

fn protocols(
    set: &IntervalSet<u8>,
    ip_version: IpVersion,
) -> Result<Vec<Option<IPProtocol>>, LowerError> {
    if set.is_full() {
        return Ok(vec![None]);
    }
    let mut out = Vec::new();
    for number in set.values() {
        let protocol = match (number, ip_version) {
            (PROTO_TCP, _) => IPProtocol::Tcp,
            (PROTO_UDP, _) => IPProtocol::Udp,
            (PROTO_ICMP, IpVersion::V4) => IPProtocol::ICMP,
            (PROTO_ICMPV6, IpVersion::V6) => IPProtocol::ICMPv6,
            (PROTO_ICMP | PROTO_ICMPV6, _) => continue,
            (other, _) => return Err(LowerError::UnrepresentableProtocol(other)),
        };
        out.push(Some(protocol));
    }
    Ok(out)
}

fn ports(set: &IntervalSet<u16>) -> Vec<Option<PortRange>> {
    if set.is_full() {
        return vec![None];
    }
    set.ranges()
        .iter()
        .map(|&(start, end)| Some(PortRange(start, end)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term() -> Term {
        Term {
            protocols: IntervalSet::full(),
            src_ip: IpSet::full(),
            dst_ip: IpSet::full(),
            src_port: IntervalSet::full(),
            dst_port: IntervalSet::full(),
        }
    }

    fn expand(term: &Term) -> Vec<FirewallRule> {
        let mut sink = RuleSink::new((), usize::MAX);
        sink.expand(term).unwrap();
        sink.into_rules()
    }

    /// Without a `/0`, nftables would install an IPv4-only rule for IPv6 too.
    #[test]
    fn address_less_rules_keep_their_family() {
        let term = Term {
            src_ip: IpSet::v4_range(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST),
            ..term()
        };
        let rules = expand(&term);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].ip_version, IpVersion::V4);
        assert_eq!(rules[0].src_ip, Some(IpRange::ANY_V4));
        assert_eq!(rules[0].dst_ip, None);
    }

    /// A rule that already names an address needs no `/0`.
    #[test]
    fn addressed_rules_are_not_pinned() {
        let host = Ipv6Addr::LOCALHOST;
        let term = Term {
            dst_ip: IpSet::v6_range(host, host),
            ..term()
        };
        let rules = expand(&term);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].src_ip, None);
        assert_eq!(rules[0].dst_ip, Some(IpRange::V6(host, 128)));
    }

    /// Shared ids would make backends merge distinct rules.
    #[test]
    fn rule_ids_are_fresh() {
        let rules = expand(&term());
        assert_eq!(rules.len(), 2);
        assert_ne!(rules[0].rule_id, rules[1].rule_id);
    }

    /// A duplicate match is skipped before it counts against the limit.
    #[test]
    fn duplicates_are_skipped() {
        let mut sink = RuleSink::new((), 2);
        sink.expand(&term()).unwrap();
        sink.expand(&term()).unwrap();
        let rules: Vec<FirewallRule> = sink.into_rules();
        assert_eq!(rules.len(), 2);
    }
}
