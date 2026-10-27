//! Which wirefilter fields are L4 fields, and what they mean.
//!
//! The lowering cannot infer meaning from a field name, so an [`L4Schema`]
//! says it outright: `ip.src` is the source address, `tcp.dst_port` is the
//! destination port of a TCP packet, `ip.proto` is the protocol spelled as a
//! name. Any field the schema does not name is refused, never ignored: a
//! dropped clause would widen the rule.
//!
//! # Presence
//!
//! A port field is set only for its own protocol (amygdala leaves
//! `tcp.dst_port` unset on a UDP packet), and wirefilter evaluates a
//! comparison against an unset field as `false`, except `!=`, which follows
//! [`Scheme::nil_not_equal_behavior`](wirefilter::Scheme::nil_not_equal_behavior).
//! [`L4Field::Port`] carries the protocol for exactly this reason: the
//! lowering rewrites `tcp.dst_port == 80` as `protocol is TCP and port is 80`,
//! which is what makes `not tcp.dst_port == 80` match UDP traffic too.
//!
//! Address and protocol fields are assumed always set: the lowering targets
//! IP packets.

use crate::set::IntervalSet;
use std::collections::HashMap;
use std::ops::RangeInclusive;

/// IANA protocol number of ICMP.
pub const PROTO_ICMP: u8 = 1;
/// IANA protocol number of TCP.
pub const PROTO_TCP: u8 = 6;
/// IANA protocol number of UDP.
pub const PROTO_UDP: u8 = 17;
/// IANA protocol number of ICMPv6.
pub const PROTO_ICMPV6: u8 = 58;

/// Which end of the flow a field describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    /// The source address or port.
    Src,
    /// The destination address or port.
    Dst,
}

/// A transport protocol that carries ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortProtocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl PortProtocol {
    /// The IANA protocol number.
    pub fn number(self) -> u8 {
        match self {
            PortProtocol::Tcp => PROTO_TCP,
            PortProtocol::Udp => PROTO_UDP,
        }
    }
}

/// The meaning of one wirefilter field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4Field {
    /// An `Ip` field holding the source or destination address.
    Ip(Side),
    /// An `Int` field holding the IANA protocol number.
    ProtocolNumber,
    /// A `Bytes` field holding a protocol name, resolved through
    /// [`L4Schema::with_protocol_name`].
    ProtocolName,
    /// An `Int` field holding a port, set only when the packet's protocol is
    /// `protocol`.
    Port {
        /// Source or destination port.
        side: Side,
        /// The protocol whose packets carry this field.
        protocol: PortProtocol,
    },
    /// A `Bool` field that is `true` exactly when the packet's protocol is
    /// this number.
    ProtocolFlag(u8),
}

/// Maps wirefilter field names onto L4 dimensions.
#[derive(Debug, Clone, Default)]
pub struct L4Schema {
    fields: HashMap<String, L4Field>,
    protocol_names: HashMap<Box<[u8]>, IntervalSet<u8>>,
}

impl L4Schema {
    /// A schema with no field.
    pub fn new() -> Self {
        Self::default()
    }

    /// The fields amygdala's scheme defines and sets per packet.
    ///
    /// `ip.proto` holds `tcp`, `udp`, `icmp` (ICMP or ICMPv6) or `other`
    /// (every other protocol).
    pub fn amygdala() -> Self {
        let tcp = PortProtocol::Tcp;
        let udp = PortProtocol::Udp;
        let known = [PROTO_ICMP, PROTO_TCP, PROTO_UDP, PROTO_ICMPV6]
            .map(IntervalSet::point)
            .iter()
            .fold(IntervalSet::empty(), |acc, set| acc.union(set));

        Self::new()
            .with_field("ip.src", L4Field::Ip(Side::Src))
            .with_field("ip.dst", L4Field::Ip(Side::Dst))
            .with_field("ip.proto", L4Field::ProtocolName)
            .with_field("tcp.src_port", port(Side::Src, tcp))
            .with_field("tcp.dst_port", port(Side::Dst, tcp))
            .with_field("udp.src_port", port(Side::Src, udp))
            .with_field("udp.dst_port", port(Side::Dst, udp))
            .with_protocol_name("tcp", [PROTO_TCP..=PROTO_TCP])
            .with_protocol_name("udp", [PROTO_UDP..=PROTO_UDP])
            .with_protocol_name(
                "icmp",
                [PROTO_ICMP..=PROTO_ICMP, PROTO_ICMPV6..=PROTO_ICMPV6],
            )
            .with_protocol_set("other", known.complement())
    }

    /// Declares the meaning of the field called `name`.
    pub fn with_field(mut self, name: impl Into<String>, field: L4Field) -> Self {
        self.fields.insert(name.into(), field);
        self
    }

    /// Declares which protocol numbers a [`L4Field::ProtocolName`] value
    /// stands for. A name never declared matches no packet.
    pub fn with_protocol_name(
        self,
        name: impl AsRef<[u8]>,
        protocols: impl IntoIterator<Item = RangeInclusive<u8>>,
    ) -> Self {
        let set = IntervalSet::from_ranges(protocols.into_iter().map(|r| (*r.start(), *r.end())));
        self.with_protocol_set(name, set)
    }

    fn with_protocol_set(mut self, name: impl AsRef<[u8]>, set: IntervalSet<u8>) -> Self {
        self.protocol_names.insert(name.as_ref().into(), set);
        self
    }

    pub(crate) fn field(&self, name: &str) -> Option<&L4Field> {
        self.fields.get(name)
    }

    pub(crate) fn protocols_named(&self, name: &[u8]) -> IntervalSet<u8> {
        self.protocol_names
            .get(name)
            .cloned()
            .unwrap_or_else(IntervalSet::empty)
    }
}

fn port(side: Side, protocol: PortProtocol) -> L4Field {
    L4Field::Port { side, protocol }
}
