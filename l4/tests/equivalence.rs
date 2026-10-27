//! The lowered rules must match exactly the packets the expression matches.
//!
//! Each expression is compiled by the wirefilter engine and lowered by this
//! crate; random packets, drawn mostly from boundary values, are run through
//! both. Any disagreement is a widened or narrowed rule. The rules are read
//! the way each Hillock backend reads them, since they disagree on where an
//! address-less rule's family comes from.

#![cfg(not(miri))]

use hillock::common::firewall_rules::validator::{
    validate_icmp, validate_ip_version, validate_port_ranges, validate_ports_have_protocol,
    validate_prefixes, validate_tcp_flags,
};
use hillock::common::{FirewallRule, IPProtocol, IpRange, IpVersion, PortRange};
use rand::rngs::StdRng;
use rand::seq::IndexedRandom;
use rand::{RngExt, SeedableRng};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use wirefilter::{ExecutionContext, Filter, Scheme, SchemeBuilder, Type};
use wirefilter_l4::{
    L4Schema, Limits, LowerError, check, check_with_limits, lower, lower_with_limits,
};

#[derive(Debug, Clone, Copy)]
struct Packet {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
}

impl Packet {
    fn has_ports(&self) -> bool {
        matches!(self.protocol, 6 | 17)
    }
}

fn scheme(nil_not_equal: bool) -> Scheme {
    // amygdala registers every field as optional.
    let mut builder = SchemeBuilder::new();
    for (name, ty) in [
        ("ip.src", Type::Ip),
        ("ip.dst", Type::Ip),
        ("ip.proto", Type::Bytes),
        ("tcp.src_port", Type::Int),
        ("tcp.dst_port", Type::Int),
        ("udp.src_port", Type::Int),
        ("udp.dst_port", Type::Int),
    ] {
        builder.add_optional_field(name, ty).unwrap();
    }
    builder.set_nil_not_equal_behavior(nil_not_equal);
    builder.build()
}

fn lower_source(source: &str, nil_not_equal: bool) -> Result<Vec<FirewallRule>, LowerError> {
    let ast = scheme(nil_not_equal).parse(source).unwrap();
    lower(&ast, &L4Schema::amygdala(), ())
}

/// What amygdala's `ctx.rs` sets for a packet.
fn filter_matches(scheme: &Scheme, filter: &Filter, packet: &Packet) -> bool {
    let mut ctx = ExecutionContext::new(scheme);
    ctx.set_field_value_from_name("ip.src", packet.src_ip)
        .unwrap();
    ctx.set_field_value_from_name("ip.dst", packet.dst_ip)
        .unwrap();
    let name = match packet.protocol {
        6 => "tcp",
        17 => "udp",
        1 | 58 => "icmp",
        _ => "other",
    };
    ctx.set_field_value_from_name("ip.proto", name).unwrap();
    let prefix = match packet.protocol {
        6 => Some("tcp"),
        17 => Some("udp"),
        _ => None,
    };
    if let Some(prefix) = prefix {
        ctx.set_field_value_from_name(&format!("{prefix}.src_port"), i64::from(packet.src_port))
            .unwrap();
        ctx.set_field_value_from_name(&format!("{prefix}.dst_port"), i64::from(packet.dst_port))
            .unwrap();
    }
    filter.execute(&ctx).unwrap()
}

/// Where a backend takes a rule's family from.
#[derive(Debug, Clone, Copy)]
enum Reading {
    /// TC and XDP: `ip_version`, compared before anything else.
    Ebpf,
    /// nftables, DOCA and WFP: the addresses, else an ICMP protocol, else
    /// both families.
    Addresses,
}

fn contains(range: IpRange, ip: IpAddr) -> bool {
    match (range, ip) {
        (IpRange::V4(net, len), IpAddr::V4(ip)) => {
            len == 0 || (net.to_bits() ^ ip.to_bits()) >> (32 - len) == 0
        }
        (IpRange::V6(net, len), IpAddr::V6(ip)) => {
            len == 0 || (net.to_bits() ^ ip.to_bits()) >> (128 - len) == 0
        }
        _ => false,
    }
}

/// A reference matcher with a Hillock backend's reading of a rule.
fn rule_matches(rule: &FirewallRule, packet: &Packet, reading: Reading) -> bool {
    let v6 = packet.src_ip.is_ipv6();
    let family = match reading {
        Reading::Ebpf => rule.ip_version == if v6 { IpVersion::V6 } else { IpVersion::V4 },
        Reading::Addresses => match (rule.src_ip.or(rule.dst_ip), rule.protocol) {
            (Some(range), _) => range.is_v6() == v6,
            (None, Some(IPProtocol::ICMP)) => !v6,
            (None, Some(IPProtocol::ICMPv6)) => v6,
            _ => true,
        },
    };
    let protocol = match rule.protocol {
        None | Some(IPProtocol::Any) => true,
        Some(IPProtocol::Tcp) => packet.protocol == 6,
        Some(IPProtocol::Udp) => packet.protocol == 17,
        Some(IPProtocol::ICMP) => packet.protocol == 1,
        Some(IPProtocol::ICMPv6) => packet.protocol == 58,
    };
    let port = |range: Option<PortRange>, value: u16| match range {
        None => true,
        Some(range) => packet.has_ports() && (range.0..=range.1).contains(&value),
    };
    family
        && rule
            .src_ip
            .is_none_or(|range| contains(range, packet.src_ip))
        && rule
            .dst_ip
            .is_none_or(|range| contains(range, packet.dst_ip))
        && protocol
        && port(rule.src_port, packet.src_port)
        && port(rule.dst_port, packet.dst_port)
}

/// Every rule passes the checks Hillock runs on the way in, nftables' family
/// check included.
fn assert_valid(source: &str, rules: &[FirewallRule]) {
    for rule in rules {
        let checks = [
            validate_tcp_flags(rule),
            validate_icmp(rule),
            validate_ports_have_protocol(rule),
            validate_port_ranges(rule),
            validate_prefixes(rule),
        ];
        for check in checks {
            check.unwrap_or_else(|err| panic!("`{source}`: {rule:?} refused: {err}"));
        }
        validate_ip_version(rule)
            .unwrap_or_else(|err| panic!("`{source}`: {rule:?} refused: {err}"));
        if let (Some(src), Some(dst)) = (rule.src_ip, rule.dst_ip) {
            assert_eq!(src.is_v6(), dst.is_v6(), "`{source}`: mixed families");
        }
    }
}

fn random_packet(rng: &mut StdRng) -> Packet {
    const V4: &[Ipv4Addr] = &[
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(9, 255, 255, 255),
        Ipv4Addr::new(10, 0, 0, 0),
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 5),
        Ipv4Addr::new(10, 0, 0, 6),
        Ipv4Addr::new(10, 0, 0, 7),
        Ipv4Addr::new(10, 0, 0, 255),
        Ipv4Addr::new(10, 0, 1, 0),
        Ipv4Addr::new(10, 0, 255, 255),
        Ipv4Addr::new(10, 1, 0, 0),
        Ipv4Addr::new(10, 1, 255, 255),
        Ipv4Addr::new(10, 2, 0, 0),
        Ipv4Addr::new(10, 255, 255, 255),
        Ipv4Addr::new(11, 0, 0, 0),
        Ipv4Addr::new(192, 167, 255, 255),
        Ipv4Addr::new(192, 168, 0, 0),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(192, 168, 255, 255),
        Ipv4Addr::new(192, 169, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
    ];
    const V6: &[Ipv6Addr] = &[
        Ipv6Addr::UNSPECIFIED,
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(
            0x2001, 0xdb7, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        Ipv6Addr::new(
            0x2001, 0xdb8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ),
        Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        Ipv6Addr::new(
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ),
    ];
    const PORTS: &[u16] = &[
        0, 1, 21, 22, 23, 52, 53, 54, 79, 80, 81, 442, 443, 444, 1023, 1024, 1025, 8079, 8080,
        8085, 8090, 8091, 65534, 65535,
    ];

    let v6 = rng.random_bool(0.3);
    let ip = |rng: &mut StdRng| -> IpAddr {
        let pooled = rng.random_bool(0.85);
        if v6 {
            IpAddr::V6(if pooled {
                *V6.choose(rng).unwrap()
            } else {
                Ipv6Addr::from_bits(rng.random())
            })
        } else {
            IpAddr::V4(if pooled {
                *V4.choose(rng).unwrap()
            } else {
                Ipv4Addr::from_bits(rng.random())
            })
        }
    };
    let port = |rng: &mut StdRng| -> u16 {
        if rng.random_bool(0.85) {
            *PORTS.choose(rng).unwrap()
        } else {
            rng.random()
        }
    };
    let icmp = if v6 { 58 } else { 1 };
    Packet {
        src_ip: ip(rng),
        dst_ip: ip(rng),
        protocol: *[6, 6, 17, 17, icmp, 47].choose(rng).unwrap(),
        src_port: port(rng),
        dst_port: port(rng),
    }
}

fn assert_equivalent(source: &str, nil_not_equal: bool) -> Vec<FirewallRule> {
    let scheme = scheme(nil_not_equal);
    let ast = scheme.parse(source).unwrap();
    let rules: Vec<FirewallRule> = lower(&ast, &L4Schema::amygdala(), ())
        .unwrap_or_else(|err| panic!("`{source}` (nil != {nil_not_equal}) failed: {err}"));
    assert_valid(source, &rules);
    let filter = ast.compile();

    let mut rng = StdRng::seed_from_u64(0x5eed);
    for _ in 0..20_000 {
        let packet = random_packet(&mut rng);
        let expected = filter_matches(&scheme, &filter, &packet);
        for reading in [Reading::Ebpf, Reading::Addresses] {
            assert_eq!(
                rules
                    .iter()
                    .any(|rule| rule_matches(rule, &packet, reading)),
                expected,
                "`{source}` (nil != {nil_not_equal}, {reading:?}) disagrees on {packet:?}\n\
                 rules: {rules:#?}"
            );
        }
    }
    rules
}

const EXACT: &[&str] = &[
    "tcp.dst_port == 80",
    "tcp.dst_port in {80 443} and ip.src in {10.0.0.0/8 192.168.0.0/16}",
    "ip.src == 1.1.1.1 or ip.dst == 2001:db8::1",
    "udp.dst_port == 53 and not ip.src in {10.0.0.0/8}",
    r#"ip.proto in {"tcp" "udp"} and ip.dst >= 10.0.0.5 and ip.dst <= 10.0.0.6"#,
    r#"ip.proto == "icmp" and ip.src in {10.0.0.1..10.0.0.6 2001:db8::/32}"#,
    "tcp.src_port >= 1024 and tcp.dst_port in {80 443 8080..8090} \
     and not (ip.src in {10.0.0.0/24} or ip.dst == 192.168.1.1)",
    r#"ip.proto == "udp" and ((udp.dst_port == 53) xor (ip.src in {10.0.0.0/8}))"#,
    r#"not (tcp.dst_port == 80 or udp.dst_port == 53) and ip.proto in {"tcp" "udp"}"#,
    "ip.src in {10.0.0.0/8} and not ip.src in {10.1.0.0/16}",
    "ip.src < 10.0.0.0 and udp.src_port < 1024",
    r#"ip.proto == "tcp" and tcp.dst_port != 22"#,
    "tcp.dst_port == 80 and udp.dst_port == 53",
    "ip.src in {10.0.0.0/8} or not ip.src in {10.0.0.0/8}",
    "(tcp.dst_port == 80 or tcp.dst_port == 443) and (ip.dst in {10.0.0.0/8} or ip.dst == 2001:db8::1)",
    // One family, no address: the Hillock rule must keep the family.
    "ip.src >= 0.0.0.0",
    "ip.dst >= :: and tcp.dst_port == 443",
];

/// Every expression in the corpus lowers to rules that agree with the engine,
/// whichever field a backend takes the family from.
#[test]
fn lowered_rules_agree_with_the_engine() {
    for source in EXACT {
        for nil_not_equal in [true, false] {
            assert_equivalent(source, nil_not_equal);
        }
    }
}

/// With nil `!=` off, `tcp.dst_port != 22` holds only for TCP and lowers;
/// with it on, it also holds for every other protocol, which no rule can name.
#[test]
fn not_equal_on_a_port_depends_on_nil_behaviour() {
    assert_equivalent("tcp.dst_port != 22", false);
    assert!(matches!(
        lower_source("tcp.dst_port != 22", true),
        Err(LowerError::UnrepresentableProtocol(_))
    ));
}

/// "Every protocol but X" has no rule; installing `Any` instead would widen
/// the rule to X.
#[test]
fn refuses_protocol_complements() {
    for source in [
        r#"ip.proto != "tcp""#,
        r#"ip.proto == "other""#,
        "not tcp.dst_port == 80",
    ] {
        assert!(
            matches!(
                lower_source(source, false),
                Err(LowerError::UnrepresentableProtocol(_))
            ),
            "`{source}` must be refused"
        );
    }
}

/// The shapes callers will see for the common cases.
#[test]
fn compact_results() {
    let rules = assert_equivalent("tcp.dst_port == 80", true);
    assert_eq!(rules.len(), 2, "{rules:#?}");
    assert!(
        rules
            .iter()
            .all(|r| r.protocol == Some(IPProtocol::Tcp) && r.dst_port == Some(PortRange(80, 80)))
    );

    let rules = assert_equivalent("ip.src in {10.0.0.0/8} and udp.dst_port == 53", true);
    assert_eq!(rules.len(), 1, "{rules:#?}");
    assert_eq!(rules[0].ip_version, IpVersion::V4);

    let rules = assert_equivalent("tcp.dst_port in {80 443} or tcp.dst_port == 8080", true);
    assert_eq!(rules.len(), 6, "{rules:#?}");

    assert!(assert_equivalent("tcp.dst_port == 80 and udp.dst_port == 53", true).is_empty());

    // Matches everything: one `/0` per family, and nothing else.
    let rules = assert_equivalent("ip.src in {10.0.0.0/8} or not ip.src in {10.0.0.0/8}", true);
    assert_eq!(rules.len(), 2, "{rules:#?}");
    assert!(
        rules
            .iter()
            .all(|r| r.src_ip.is_some_and(|ip| ip.prefix() == 0)
                && r.dst_ip.is_none()
                && r.protocol.is_none())
    );
}

/// `check` answers exactly what `lower` would: a corpus expression passes,
/// and a refused one fails with the same error.
#[test]
fn check_agrees_with_lower() {
    let refused = [
        r#"ip.proto != "tcp""#,
        r#"ip.proto == "other""#,
        "not tcp.dst_port == 80",
        "tcp.dst_port != 22",
    ];
    for source in EXACT.iter().chain(&refused) {
        for nil_not_equal in [true, false] {
            let ast = scheme(nil_not_equal).parse(source).unwrap();
            assert_eq!(
                check(&ast, &L4Schema::amygdala()),
                lower_source(source, nil_not_equal).map(drop),
                "`{source}` (nil != {nil_not_equal})"
            );
        }
    }

    let mut unknown = SchemeBuilder::new();
    unknown.add_field("http.host", Type::Bytes).unwrap();
    let ast = unknown.build().parse(r#"http.host == "a""#).unwrap();
    assert_eq!(
        check(&ast, &L4Schema::amygdala()),
        Err(LowerError::UnknownField("http.host".into()))
    );
}

/// The limits count the same rules in both.
#[test]
fn check_honours_limits() {
    let ast = scheme(true).parse("tcp.dst_port in {80 443}").unwrap();
    let limits = Limits {
        max_rules: 3,
        ..Limits::default()
    };
    let lowered: Result<Vec<FirewallRule>, _> =
        lower_with_limits(&ast, &L4Schema::amygdala(), (), limits);
    assert_eq!(
        lowered.map(drop),
        Err(LowerError::TooManyRules { limit: 3 })
    );
    assert_eq!(
        check_with_limits(&ast, &L4Schema::amygdala(), limits),
        Err(LowerError::TooManyRules { limit: 3 })
    );
    assert_eq!(
        check_with_limits(
            &ast,
            &L4Schema::amygdala(),
            Limits {
                max_rules: 4,
                ..limits
            }
        ),
        Ok(())
    );
}
