//! Sets of values over one packet dimension.
//!
//! Every predicate the lowering understands is a set: `tcp.dst_port in {80
//! 443}` is the port set `{80, 443}`, `ip.src >= 10.0.0.0` the address set
//! `10.0.0.0..=255.255.255.255`. Negation is a complement and conjunction an
//! intersection, so a minimised cube collapses to one set per dimension
//! without ever enumerating values.
//!
//! [`IntervalSet`] keeps its ranges sorted, disjoint and non-adjacent, which
//! makes the representation canonical: two sets holding the same values are
//! `==` and hash alike, and the atom table relies on that to deduplicate.

use std::fmt::Debug;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};

/// An unsigned integer domain an [`IntervalSet`] ranges over.
pub trait Point: Copy + Ord + Debug + Hash {
    /// Smallest value of the domain.
    const MIN: Self;
    /// Largest value of the domain.
    const MAX: Self;

    /// The next value, or `None` at [`Point::MAX`].
    fn succ(self) -> Option<Self>;

    /// The previous value, or `None` at [`Point::MIN`].
    fn pred(self) -> Option<Self>;
}

macro_rules! impl_point {
    ($($ty:ty),*) => {$(
        impl Point for $ty {
            const MIN: Self = <$ty>::MIN;
            const MAX: Self = <$ty>::MAX;

            #[inline]
            fn succ(self) -> Option<Self> {
                self.checked_add(1)
            }

            #[inline]
            fn pred(self) -> Option<Self> {
                self.checked_sub(1)
            }
        }
    )*};
}

impl_point!(u8, u16, u32, u128);

/// A set of values of `T`, stored as inclusive ranges.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct IntervalSet<T> {
    ranges: Vec<(T, T)>,
}

impl<T: Point> IntervalSet<T> {
    /// The set holding no value.
    pub fn empty() -> Self {
        Self { ranges: Vec::new() }
    }

    /// The set holding every value of the domain.
    pub fn full() -> Self {
        Self {
            ranges: vec![(T::MIN, T::MAX)],
        }
    }

    /// The set holding `start..=end`; empty when `start > end`.
    pub fn range(start: T, end: T) -> Self {
        if start > end {
            Self::empty()
        } else {
            Self {
                ranges: vec![(start, end)],
            }
        }
    }

    /// The set holding exactly `value`.
    pub fn point(value: T) -> Self {
        Self::range(value, value)
    }

    /// The union of arbitrary, possibly overlapping, ranges.
    pub fn from_ranges(ranges: impl IntoIterator<Item = (T, T)>) -> Self {
        let mut ranges: Vec<_> = ranges.into_iter().filter(|(s, e)| s <= e).collect();
        ranges.sort_unstable();

        let mut merged: Vec<(T, T)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if last.1.succ().is_none_or(|next| start <= next) => {
                    last.1 = last.1.max(end);
                }
                _ => merged.push((start, end)),
            }
        }
        Self { ranges: merged }
    }

    /// The inclusive ranges, sorted, disjoint and non-adjacent.
    pub fn ranges(&self) -> &[(T, T)] {
        &self.ranges
    }

    /// Whether the set holds no value.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Whether the set holds every value of the domain.
    pub fn is_full(&self) -> bool {
        self.ranges == [(T::MIN, T::MAX)]
    }

    /// Whether the set holds `value`.
    #[cfg(test)]
    pub fn contains(&self, value: T) -> bool {
        self.ranges
            .binary_search_by(|&(start, end)| {
                if end < value {
                    std::cmp::Ordering::Less
                } else if start > value {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    /// Values in either set.
    pub fn union(&self, other: &Self) -> Self {
        Self::from_ranges(self.ranges.iter().chain(&other.ranges).copied())
    }

    /// Values in both sets.
    pub fn intersection(&self, other: &Self) -> Self {
        let (mut i, mut j) = (0, 0);
        let mut out = Vec::new();
        while i < self.ranges.len() && j < other.ranges.len() {
            let (a_start, a_end) = self.ranges[i];
            let (b_start, b_end) = other.ranges[j];
            let start = a_start.max(b_start);
            let end = a_end.min(b_end);
            if start <= end {
                out.push((start, end));
            }
            if a_end < b_end {
                i += 1;
            } else {
                j += 1;
            }
        }
        Self { ranges: out }
    }

    /// Values of the domain not in the set.
    pub fn complement(&self) -> Self {
        let mut out = Vec::with_capacity(self.ranges.len() + 1);
        let mut next = Some(T::MIN);
        for &(start, end) in &self.ranges {
            if let Some(from) = next
                && from < start
            {
                out.push((from, start.pred().expect("start > MIN")));
            }
            next = end.succ();
        }
        if let Some(from) = next {
            out.push((from, T::MAX));
        }
        Self { ranges: out }
    }

    /// Values in `self` but not in `other`.
    pub fn difference(&self, other: &Self) -> Self {
        self.intersection(&other.complement())
    }

    /// Whether every value of `self` is in `other`.
    pub fn is_subset(&self, other: &Self) -> bool {
        self.difference(other).is_empty()
    }

    /// Whether the sets share no value.
    pub fn is_disjoint(&self, other: &Self) -> bool {
        self.intersection(other).is_empty()
    }

    /// Every value, in order. Only sensible for small sets.
    pub fn values(&self) -> impl Iterator<Item = T> + '_ {
        self.ranges.iter().flat_map(|&(start, end)| {
            std::iter::successors(Some(start), move |&v| v.succ().filter(|&n| n <= end))
        })
    }
}

/// A set of IP addresses, one [`IntervalSet`] per family.
///
/// The families are disjoint domains: wirefilter never orders an IPv4 against
/// an IPv6 address, so `ip.src < 10.0.0.0` holds no IPv6 address while
/// `ip.src != 10.0.0.1` holds all of them.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct IpSet {
    /// IPv4 addresses, as their `u32` value.
    pub v4: IntervalSet<u32>,
    /// IPv6 addresses, as their `u128` value.
    pub v6: IntervalSet<u128>,
}

impl IpSet {
    /// The set holding no address.
    pub fn empty() -> Self {
        Self {
            v4: IntervalSet::empty(),
            v6: IntervalSet::empty(),
        }
    }

    /// The set holding every address of both families.
    pub fn full() -> Self {
        Self {
            v4: IntervalSet::full(),
            v6: IntervalSet::full(),
        }
    }

    /// The IPv4 addresses `start..=end`.
    pub fn v4_range(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self {
            v4: IntervalSet::range(start.to_bits(), end.to_bits()),
            v6: IntervalSet::empty(),
        }
    }

    /// The IPv6 addresses `start..=end`.
    pub fn v6_range(start: Ipv6Addr, end: Ipv6Addr) -> Self {
        Self {
            v4: IntervalSet::empty(),
            v6: IntervalSet::range(start.to_bits(), end.to_bits()),
        }
    }

    /// Whether the set holds no address.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Whether the set holds every address of both families.
    pub fn is_full(&self) -> bool {
        self.v4.is_full() && self.v6.is_full()
    }

    /// Addresses in either set.
    pub fn union(&self, other: &Self) -> Self {
        Self {
            v4: self.v4.union(&other.v4),
            v6: self.v6.union(&other.v6),
        }
    }

    /// Addresses in both sets.
    pub fn intersection(&self, other: &Self) -> Self {
        Self {
            v4: self.v4.intersection(&other.v4),
            v6: self.v6.intersection(&other.v6),
        }
    }

    /// Addresses of both families not in the set.
    pub fn complement(&self) -> Self {
        Self {
            v4: self.v4.complement(),
            v6: self.v6.complement(),
        }
    }

    /// Whether every address of `self` is in `other`.
    pub fn is_subset(&self, other: &Self) -> bool {
        self.v4.is_subset(&other.v4) && self.v6.is_subset(&other.v6)
    }

    /// Whether the sets share no address.
    pub fn is_disjoint(&self, other: &Self) -> bool {
        self.v4.is_disjoint(&other.v4) && self.v6.is_disjoint(&other.v6)
    }
}

/// The fewest `(network, prefix length)` blocks covering `start..=end` exactly,
/// in a `bits`-wide address space.
pub fn range_to_prefixes(start: u128, end: u128, bits: u32) -> Vec<(u128, u8)> {
    // Inclusive span of a block with `host_bits` host bits, without overflowing
    // at a 128-bit block.
    fn span(host_bits: u32) -> u128 {
        if host_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        }
    }

    let mut out = Vec::new();
    let mut lo = start;
    loop {
        let mut host_bits = if lo == 0 {
            bits
        } else {
            lo.trailing_zeros().min(bits)
        };
        while lo + span(host_bits) > end {
            host_bits -= 1;
        }
        let last = lo + span(host_bits);
        out.push((lo, (bits - host_bits) as u8));
        if last >= end {
            return out;
        }
        lo = last + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Adjacent ranges left unmerged would make equal sets compare unequal and
    /// split one atom into two.
    #[test]
    fn from_ranges_merges_overlapping_and_adjacent() {
        let set = IntervalSet::<u16>::from_ranges([(10, 20), (21, 30), (5, 12), (40, 40)]);
        assert_eq!(set.ranges(), &[(5, 30), (40, 40)]);
    }

    /// A merge that computed `MAX + 1` would panic on a range ending at the top.
    #[test]
    fn from_ranges_handles_domain_maximum() {
        let set = IntervalSet::<u8>::from_ranges([(250, 255), (200, 255)]);
        assert_eq!(set.ranges(), &[(200, 255)]);
    }

    /// A complement that lost either end of the domain would widen or narrow
    /// every negated predicate.
    #[test]
    fn complement_covers_both_ends() {
        let set = IntervalSet::<u16>::from_ranges([(0, 9), (80, 80), (65535, 65535)]);
        assert_eq!(set.complement().ranges(), &[(10, 79), (81, 65534)]);
        assert_eq!(set.complement().complement(), set);
        assert!(IntervalSet::<u8>::empty().complement().is_full());
        assert!(IntervalSet::<u8>::full().complement().is_empty());
    }

    /// A wrong intersection would let a cube match ports none of its literals
    /// allow.
    #[test]
    fn intersection_and_relations() {
        let a = IntervalSet::<u16>::from_ranges([(1, 100), (200, 300)]);
        let b = IntervalSet::<u16>::from_ranges([(50, 250)]);
        assert_eq!(a.intersection(&b).ranges(), &[(50, 100), (200, 250)]);
        assert!(IntervalSet::point(80).is_subset(&a));
        assert!(IntervalSet::point(150).is_disjoint(&a));
        assert!(a.contains(250) && !a.contains(150));
    }

    /// A block that crossed its alignment boundary would cover addresses
    /// outside the range.
    #[test]
    fn prefixes_are_exact() {
        // 10.0.0.1 ..= 10.0.0.6 -> /32, /31, /31, /32
        let start = u32::from(Ipv4Addr::new(10, 0, 0, 1)) as u128;
        let end = u32::from(Ipv4Addr::new(10, 0, 0, 6)) as u128;
        let blocks = range_to_prefixes(start, end, 32);
        assert_eq!(
            blocks,
            vec![
                (start, 32),
                (start + 1, 31),
                (start + 3, 31),
                (start + 5, 32),
            ]
        );
    }

    /// The whole space must be one /0, not an overflow.
    #[test]
    fn prefixes_of_full_space() {
        assert_eq!(range_to_prefixes(0, u32::MAX as u128, 32), vec![(0, 0)]);
        assert_eq!(range_to_prefixes(0, u128::MAX, 128), vec![(0, 0)]);
        assert_eq!(
            range_to_prefixes(1, u128::MAX, 128).last(),
            Some(&(1u128 << 127, 1))
        );
    }
}
