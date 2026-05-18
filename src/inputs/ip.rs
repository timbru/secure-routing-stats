use std::{cmp, collections::HashMap, fmt, net, num::ParseIntError, ops::Range, str::FromStr};

use serde::{Deserialize, Serialize, Serializer, de};

use intervaltree::IntervalTree;

// https://tools.ietf.org/html/rfc4291#section-2.5.5
const IPV4_IN_IPV6: u128 = 0xffff_0000_0000;
const IPV4_UNUSED: u128 = 0xffff_ffff_ffff_ffff_ffff_ffff_0000_0000;

//------------ IpAddressFamily -----------------------------------------------

#[derive(Debug, PartialEq)]
pub enum IpAddressFamily {
    Ipv4,
    Ipv6,
}

//------------ IpAddress -----------------------------------------------------

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IpAddress {
    value: u128,
}

impl IpAddress {
    /// Use with extreme prejudice. New IPv4 numbers should be specified as
    /// IPV4_IN_IPV6 | value
    fn new(value: u128) -> Self {
        IpAddress { value }
    }

    pub fn to_net_ipaddr(&self) -> net::IpAddr {
        match self.ip_address_family() {
            IpAddressFamily::Ipv4 => net::IpAddr::V4(net::Ipv4Addr::from(self.value as u32)),
            IpAddressFamily::Ipv6 => net::IpAddr::V6(net::Ipv6Addr::from(self.value)),
        }
    }
    pub fn ip_address_family(&self) -> IpAddressFamily {
        if self.value & IPV4_UNUSED == IPV4_IN_IPV6 {
            IpAddressFamily::Ipv4
        } else {
            IpAddressFamily::Ipv6
        }
    }
}

impl fmt::Debug for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_net_ipaddr().fmt(f)
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_net_ipaddr().fmt(f)
    }
}

impl Serialize for IpAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl FromStr for IpAddress {
    type Err = IpAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('.') {
            let ipv4 = net::Ipv4Addr::from_str(s)?;
            let mut value: u128 = 0;
            for octet in &ipv4.octets() {
                value <<= 8;
                value += u128::from(*octet);
            }
            Ok(IpAddress {
                value: IPV4_IN_IPV6 | value,
            })
        } else if s.contains(':') {
            let ipv6 = net::Ipv6Addr::from_str(s)?;
            let mut value = 0;
            for octet in &ipv6.octets() {
                value <<= 8;
                value += u128::from(*octet);
            }
            Ok(IpAddress { value })
        } else {
            Err(IpAddressError::NotAnIpAddress)
        }
    }
}

//------------ IpRange -------------------------------------------------------

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IpRange {
    /// The first address included in this range
    min: IpAddress,

    /// The last address included in this range
    max: IpAddress,
}

impl IpRange {
    pub fn create(min: IpAddress, max: IpAddress) -> Result<Self, IpRangeError> {
        if min.ip_address_family() != max.ip_address_family() {
            Err(IpRangeError::AddressFamilyMismatch)
        } else if min.value > max.value {
            Err(IpRangeError::MinExceedsMax)
        } else {
            Ok(IpRange { min, max })
        }
    }

    pub fn from_min_and_number(min: IpAddress, number: u128) -> Result<Self, IpRangeError> {
        let value = min.value + number - 1;
        let max = IpAddress { value };
        Self::create(min, max)
    }

    pub fn is_prefix(&self) -> bool {
        // The following code is inspired by the RIPE NCC ip-resource java library
        // https://github.com/RIPE-NCC/ipresource/blob/master/src/main/java/net/ripe/ipresource/IpRange.java

        // First get the size of the largest common denominator
        let lead_in_common = (self.min.value ^ self.max.value).leading_zeros();

        // Lower bound is then derived by keeping all bits in common from the
        // min value, and setting the remainder to 0s. This has to match the
        // value for self.min.value itself for this to be a valid prefix
        let lower_bound = self.min.value & u128::MAX << (128 - lead_in_common);

        // Upper bound is then derived by keeping all the bits in common from
        // min value, and setting the remainder to 1s. This has to match the
        // value for self.max.value
        let upper_bound = lower_bound | ((1u128 << (128 - lead_in_common)) - 1);

        self.min.value == lower_bound && self.max.value == upper_bound
    }

    /// Returns the IpAddressFamily for this.
    pub fn ip_address_family(&self) -> IpAddressFamily {
        // Create ensures that the address family is the same for min and max
        self.min.ip_address_family()
    }

    /// Returns the number of IpAddresses contained in this range
    pub fn size(&self) -> u128 {
        self.max.value - self.min.value + 1
    }

    /// Returns true if the ranges have any overlap
    pub fn intersects(&self, other: IpRange) -> bool {
        (self.min.value <= other.min.value && self.max.value >= other.min.value)
            || (self.min.value > other.min.value && self.min.value <= other.max.value)
    }

    /// Returns true if the ranges are adjacent.
    /// i.e. one range ends at the IpAddres before the other begins.
    pub fn is_adjacent(&self, other: IpRange) -> bool {
        self.min.value == other.max.value + 1 || self.max.value + 1 == other.min.value
    }

    pub fn contains(&self, other: &Range<u128>) -> bool {
        self.min.value <= other.start && self.max.value >= other.end
    }

    pub fn is_contained_by(&self, other: &Range<u128>) -> bool {
        IpRange::from(other).contains(&self.to_range())
    }

    pub fn to_range(&self) -> std::ops::Range<u128> {
        std::ops::Range {
            start: self.min.value,
            end: self.max.value,
        }
    }
}

impl fmt::Debug for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.min, self.max)
    }
}

impl Serialize for IpRange {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl FromStr for IpRange {
    type Err = IpRangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip_values: Vec<&str> = s.split('-').collect();

        if ip_values.len() != 2 {
            return Err(IpRangeError::MustUseDashNotation);
        }

        let min = IpAddress::from_str(ip_values[0])?;
        let max = IpAddress::from_str(ip_values[1])?;
        let range = IpRange::create(min, max)?;
        Ok(range)
    }
}

impl From<&Range<u128>> for IpRange {
    fn from(r: &Range<u128>) -> Self {
        let min = IpAddress { value: r.start };
        let max = IpAddress { value: r.end };
        IpRange { min, max }
    }
}

impl Ord for IpRange {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.min
            .value
            .cmp(&other.min.value)
            .then(self.max.value.cmp(&other.max.value))
    }
}

impl PartialOrd for IpRange {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

//------------ IpPrefix ------------------------------------------------------

#[derive(Clone)]
pub struct IpPrefix {
    range: IpRange,
    length: u8,
}

impl IpPrefix {
    pub fn length(&self) -> u8 {
        self.length
    }

    pub fn nr_of_ips(&self) -> u128 {
        self.range.max.value - self.range.min.value + 1
    }

    pub fn ip_address_family(&self) -> IpAddressFamily {
        self.range.ip_address_family()
    }

    /// Returns true if this is
    /// IPv4 /8 up to /24
    /// IPv6 /12 up to /48
    pub fn has_routable_prefix_length(&self) -> bool {
        match self.ip_address_family() {
            IpAddressFamily::Ipv4 => self.length >= 8 && self.length <= 24,
            IpAddressFamily::Ipv6 => self.length >= 12 && self.length <= 48,
        }
    }
}

impl FromStr for IpPrefix {
    type Err = IpPrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip_values: Vec<&str> = s.split('/').collect();

        if ip_values.len() != 2 {
            return Err(IpPrefixError::InvalidSyntax);
        }

        let min = IpAddress::from_str(ip_values[0])?;
        let length: u8 = u8::from_str(ip_values[1])?;

        let full_length = match min.ip_address_family() {
            IpAddressFamily::Ipv4 => length + 96,
            IpAddressFamily::Ipv6 => length,
        };

        if full_length > 128 || full_length < (128 - min.value.trailing_zeros() as u8) {
            return Err(IpPrefixError::InvalidPrefixLength);
        }

        // Logic taken from the rpki.rs implementation.
        let max_value = if full_length >= 128 {
            min.value
        } else {
            min.value | (u128::MAX >> full_length)
        };

        let max = IpAddress::new(max_value);

        let range = IpRange { min, max };

        Ok(IpPrefix { range, length })
    }
}

impl AsRef<IpRange> for IpPrefix {
    fn as_ref(&self) -> &IpRange {
        &self.range
    }
}

impl fmt::Debug for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", &self.range.min, self.length)
    }
}

impl Serialize for IpPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IpPrefix {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(d)?.to_ascii_lowercase();
        IpPrefix::from_str(&s).map_err(de::Error::custom)
    }
}

impl From<IpPrefix> for IpRange {
    fn from(pfx: IpPrefix) -> Self {
        pfx.range
    }
}

//------------ IpResourceSet -------------------------------------------------

#[derive(Clone, Eq, PartialEq)]
pub struct IpResourceSet {
    ranges: Vec<IpRange>,
}

impl IpResourceSet {
    pub fn empty() -> Self {
        IpResourceSet { ranges: vec![] }
    }

    // Returns the intersecting IpRanges as the left return value, and non-intersecting as the right.
    fn partition_intersecting_or_adjacent(
        &self,
        ip_range: IpRange,
    ) -> (Vec<IpRange>, Vec<IpRange>) {
        self.ranges
            .iter()
            .partition(|i| i.intersects(ip_range) || i.is_adjacent(ip_range))
    }

    /// Adds a range to the set, automatically joins intersecting ranges.
    pub fn add_ip_range(&mut self, ip_range: IpRange) {
        let (intersecting, mut keep) = self.partition_intersecting_or_adjacent(ip_range);

        let mut min = ip_range.min.value;
        let mut max = ip_range.max.value;
        for e in intersecting.iter() {
            min = cmp::min(min, e.min.value);
            max = cmp::max(max, e.max.value);
        }

        let range_to_add = IpRange::create(IpAddress::new(min), IpAddress::new(max));

        keep.extend(range_to_add);
        keep.sort();

        self.ranges = keep;
    }

    pub fn add_ip_address(&mut self, ip_address: IpAddress) {
        let range = IpRange {
            min: ip_address,
            max: ip_address,
        };
        self.add_ip_range(range);
    }

    pub fn remove_ip_resource_set(&mut self, other_set: &IpResourceSet) {
        for range in other_set.ranges() {
            self.remove_ip_range(*range);
        }
        self.ranges.sort();
    }

    pub fn remove_ip_range(&mut self, range_to_remove: IpRange) {
        let (intersecting, mut keep) = self.partition_intersecting_or_adjacent(range_to_remove);

        for intersecting_range in intersecting.iter() {
            if range_to_remove.max.value < intersecting_range.max.value {
                // Something on the right should remain
                keep.extend(IpRange::create(
                    IpAddress::new(range_to_remove.max.value + 1),
                    IpAddress::new(intersecting_range.max.value),
                ));
            }

            if range_to_remove.min.value > intersecting_range.min.value {
                // Something on the left should remain
                keep.extend(IpRange::create(
                    IpAddress::new(intersecting_range.min.value),
                    IpAddress::new(range_to_remove.min.value - 1),
                ));
            }
        }

        keep.sort();
        self.ranges = keep;
    }

    pub fn ranges(&self) -> &Vec<IpRange> {
        &self.ranges
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

impl FromStr for IpResourceSet {
    type Err = IpResourceSetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let string = s.replace(' ', ""); // rem. whitespace
        let mut ranges = vec![];
        for s in string.split(',') {
            if s.contains('/') {
                let pfx = IpPrefix::from_str(s)?;
                ranges.push(pfx.range)
            } else {
                let range = IpRange::from_str(s)?;
                ranges.push(range);
            }
        }

        Ok(IpResourceSet { ranges })
    }
}

impl fmt::Debug for IpResourceSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for IpResourceSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let len = self.ranges.len();
        let last = len - 1;
        for i in 0..len {
            self.ranges[i].fmt(f)?;
            if i != last {
                write!(f, ",")?;
            }
        }
        Ok(())
    }
}

impl Serialize for IpResourceSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IpResourceSet {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        IpResourceSet::from_str(&string).map_err(de::Error::custom)
    }
}

//------------ IpRangeTree --------------------------------------------------

/// Supports indexing and cheap matching of IpRanges
#[derive(Debug)]
pub struct IpRangeTree<V: AsRef<IpRange>> {
    tree: IntervalTree<u128, Vec<V>>,
}

impl<V: AsRef<IpRange>> IpRangeTree<V> {
    pub fn new(tree: IntervalTree<u128, Vec<V>>) -> Self {
        IpRangeTree { tree }
    }

    pub fn matching_or_less_specific(&self, range: &IpRange) -> Vec<&V> {
        let mut res = vec![];
        for el in self.tree.query(range.to_range()) {
            if range.is_contained_by(&el.range) {
                for matching_range in &el.value {
                    res.push(matching_range)
                }
            }
        }
        res
    }

    pub fn matching_or_more_specific(&self, range: &IpRange) -> Vec<&V> {
        let mut res = vec![];
        for el in self.tree.query(range.to_range()) {
            if range.contains(&el.range) {
                for matching_range in &el.value {
                    res.push(matching_range)
                }
            }
        }
        res
    }

    pub fn all(&self) -> Vec<&V> {
        let mut res = vec![];
        for el in self.tree.iter() {
            for range in &el.value {
                res.push(range)
            }
        }
        res
    }

    pub fn inner(&self) -> &IntervalTree<u128, Vec<V>> {
        &self.tree
    }
}

pub struct IpRangeTreeBuilder<V: AsRef<IpRange>> {
    values: HashMap<Range<u128>, Vec<V>>,
}

impl<V: AsRef<IpRange>> IpRangeTreeBuilder<V> {
    pub fn empty() -> Self {
        IpRangeTreeBuilder {
            values: HashMap::new(),
        }
    }

    pub fn add(&mut self, value: V) {
        let ip_range = value.as_ref().to_range();

        let entry = self.values.entry(ip_range).or_default();
        entry.push(value);
    }

    pub fn build(self) -> IpRangeTree<V> {
        IpRangeTree {
            tree: self.values.into_iter().collect(),
        }
    }
}

//------------ Errors -------------------------------------------------------

#[derive(Debug, Display)]
pub enum IpAddressError {
    #[display(fmt = "{}", _0)]
    AddrParseError(net::AddrParseError),

    #[display(fmt = "Pattern doesn't match IPv4 or IPv6")]
    NotAnIpAddress,
}

impl From<net::AddrParseError> for IpAddressError {
    fn from(e: net::AddrParseError) -> Self {
        IpAddressError::AddrParseError(e)
    }
}

#[derive(Debug, Display)]
pub enum IpRangeError {
    #[display(fmt = "Minimum value exceeds maximum value")]
    MinExceedsMax,

    #[display(fmt = "Min and max value need to be the same address family")]
    AddressFamilyMismatch,

    #[display(fmt = "Expected two IP addresses separated by '-' and no whitespace")]
    MustUseDashNotation,

    #[display(fmt = "Contains invalid IP address: {}", _0)]
    ContainsInvalidIpAddress(IpAddressError),
}

impl From<IpAddressError> for IpRangeError {
    fn from(e: IpAddressError) -> IpRangeError {
        IpRangeError::ContainsInvalidIpAddress(e)
    }
}

#[derive(Debug, Display)]
pub enum IpPrefixError {
    #[display(fmt = "Invalid syntax. Expect: address/length")]
    InvalidSyntax,

    #[display(fmt = "Invalid prefix length")]
    InvalidPrefixLength,

    #[display(fmt = "Base address invalid: {}", _0)]
    InvalidBaseAddress(IpAddressError),
}

impl From<IpAddressError> for IpPrefixError {
    fn from(e: IpAddressError) -> IpPrefixError {
        IpPrefixError::InvalidBaseAddress(e)
    }
}

impl From<ParseIntError> for IpPrefixError {
    fn from(_: ParseIntError) -> IpPrefixError {
        IpPrefixError::InvalidPrefixLength
    }
}

#[derive(Debug, Display)]
pub enum IpResourceSetError {
    #[display(fmt = "Invalid syntax. Expect comma separated prefixes/ranges")]
    InvalidSyntax,

    #[display(fmt = "{}", _0)]
    IpRangeError(IpRangeError),

    #[display(fmt = "{}", _0)]
    IpPrefixError(IpPrefixError),
}

impl From<IpRangeError> for IpResourceSetError {
    fn from(e: IpRangeError) -> Self {
        IpResourceSetError::IpRangeError(e)
    }
}

impl From<IpPrefixError> for IpResourceSetError {
    fn from(e: IpPrefixError) -> Self {
        IpResourceSetError::IpPrefixError(e)
    }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns an IpAddress for a &str. Panics if it can't be parsed.
    fn ip_addr(s: &str) -> IpAddress {
        IpAddress::from_str(s).unwrap()
    }

    /// Returns an IpRange for a &str. Panics if it can't be parsed.
    fn ip_range(s: &str) -> IpRange {
        IpRange::from_str(s).unwrap()
    }

    /// Returns an IpPrefix for a &str. Panics if it can't be parsed.
    fn ip_prefix(s: &str) -> IpPrefix {
        IpPrefix::from_str(s).unwrap()
    }

    #[test]
    fn test_make_ipv4_from_string() {
        assert_eq!(IPV4_IN_IPV6, ip_addr("0.0.0.0").value);
        assert_eq!(IPV4_IN_IPV6 | 255, ip_addr("0.0.0.255").value);
        assert_eq!(IPV4_IN_IPV6 | 256, ip_addr("0.0.1.0").value);
        assert_eq!(IPV4_IN_IPV6 | 65535, ip_addr("0.0.255.255").value);
        assert_eq!(IPV4_IN_IPV6 | 65536, ip_addr("0.1.0.0").value);
        assert_eq!(IPV4_IN_IPV6 | 16_777_216, ip_addr("1.0.0.0").value);

        assert!(IpAddress::from_str("yadiyada").is_err());
        assert!(IpAddress::from_str("").is_err());
        assert!(IpAddress::from_str("1.1").is_err());
    }

    #[test]
    fn test_is_ipv4() {
        assert_eq!(
            IpAddressFamily::Ipv4,
            ip_addr("0.0.0.0").ip_address_family()
        );
        assert_eq!(
            IpAddressFamily::Ipv4,
            ip_addr("10.0.0.0").ip_address_family()
        );
        assert_eq!(
            IpAddressFamily::Ipv4,
            ip_addr("255.255.255.255").ip_address_family()
        );
    }

    #[test]
    fn test_range_invalid_if_min_bigger_than_max() {
        let min = IpAddress::new(128);
        let max = IpAddress::new(0);
        let range = IpRange::create(min, max);
        assert!(range.is_err());
    }

    #[test]
    fn test_range_is_prefix() {
        assert!(ip_range("10.0.0.0-10.0.255.255").is_prefix());
        assert!(ip_range("10.0.0.0-10.1.255.255").is_prefix());
        assert!(ip_range("0.0.0.0-1.255.255.255").is_prefix());
        assert!(ip_range("2.0.0.0-3.255.255.255").is_prefix());
        assert!(ip_range("0.0.0.0-3.255.255.255").is_prefix());
        assert!(ip_range("4.0.0.0-5.255.255.255").is_prefix());
        assert!(ip_range("4.0.0.0-4.0.0.0").is_prefix());
        assert!(!ip_range("0.0.0.255-0.0.1.255").is_prefix());
        assert!(!ip_range("2.0.0.0-5.255.255.255").is_prefix());
        assert!(!ip_range("0.0.0.0-2.255.255.255").is_prefix());
        assert!(!ip_range("10.0.0.0-10.0.255.254").is_prefix());
        assert!(!ip_range("10.0.0.0-10.0.254.255").is_prefix());
        assert!(!ip_range("0.0.0.128-0.0.1.127").is_prefix());
    }

    #[test]
    fn test_range_from_start_and_number() {
        let range = ip_range("10.0.0.0-10.0.0.255");
        let range_with_number = IpRange::from_min_and_number(ip_addr("10.0.0.0"), 256).unwrap();

        assert_eq!(range, range_with_number);
    }

    #[test]
    fn test_parse_prefix() {
        assert!(IpPrefix::from_str("10.0.0.0/8").is_ok());
        assert!(IpPrefix::from_str("0.0.0.0/0").is_ok());
        assert!(IpPrefix::from_str("0.0.0.0/-1").is_err());
        assert!(IpPrefix::from_str("10.0.0.0/6").is_err());
        assert!(IpPrefix::from_str("10.0.0.0/33").is_err());
    }

    #[test]
    fn test_ip_range_intersects() {
        let range = ip_range("10.0.0.0-10.0.0.255");
        let intersecting_start = ip_range("9.0.0.0-10.0.0.0");
        let intersecting_end = ip_range("10.0.0.255-10.1.0.0");
        let exact_overlap = ip_range("10.0.0.0-10.0.0.255");
        let more_specific = ip_range("10.0.0.0-10.0.0.255");

        assert!(range.intersects(intersecting_start));
        assert!(range.intersects(intersecting_end));
        assert!(range.intersects(exact_overlap));
        assert!(range.intersects(more_specific));

        let below = ip_range("1.0.0.0-9.255.255.255");
        let above = ip_range("10.0.1.0-19.255.255.255");

        assert!(!range.intersects(below));
        assert!(!range.intersects(above));
    }

    #[test]
    fn test_ip_resource_set_functions() {
        let range = ip_range("10.0.0.0-10.0.0.255");

        let mut set = IpResourceSet::empty();
        set.add_ip_range(range);

        assert_eq!(set.ranges, vec![range]);

        let intersecting_start = ip_range("9.0.0.0-10.0.0.0");
        let expected_combined_range = ip_range("9.0.0.0-10.0.0.255");
        set.add_ip_range(intersecting_start);
        assert_eq!(set.ranges, vec![expected_combined_range]);

        let other_range = ip_range("192.168.0.0-192.168.0.1");
        set.add_ip_range(other_range);
        assert_eq!(set.ranges, vec![expected_combined_range, other_range]);
    }

    #[test]
    fn test_ip_resource_set_remove() {
        let range = ip_range("10.0.0.0-10.0.0.255");
        let mut set = IpResourceSet::empty();
        set.add_ip_range(range);

        let intersecting_start = ip_range("9.0.0.0-10.0.0.0");
        set.remove_ip_range(intersecting_start);
        assert_eq!(set.ranges, vec![ip_range("10.0.0.1-10.0.0.255")]);

        let start_left_hand = ip_range("10.0.0.1-10.0.0.2");
        set.remove_ip_range(start_left_hand);
        assert_eq!(set.ranges, vec![ip_range("10.0.0.3-10.0.0.255")]);

        let middle = ip_range("10.0.0.10-10.0.0.11");
        set.remove_ip_range(middle);
        assert_eq!(
            set.ranges,
            vec![
                ip_range("10.0.0.3-10.0.0.9"),
                ip_range("10.0.0.12-10.0.0.255")
            ]
        );

        let exact_match = ip_range("10.0.0.3-10.0.0.9");
        set.remove_ip_range(exact_match);
        assert_eq!(set.ranges, vec![ip_range("10.0.0.12-10.0.0.255")]);

        let encompassing = ip_range("10.0.0.0-10.0.0.255");
        set.remove_ip_range(encompassing);
        assert_eq!(set.ranges, vec![]);
    }

    #[test]
    fn test_ip_resource_set_remove_other_set() {
        let mut set = IpResourceSet::empty();
        set.add_ip_range(ip_range("10.0.0.0-10.0.0.255"));
        set.add_ip_range(ip_prefix("2001:DB8::/32").range);

        let mut other_set = IpResourceSet::empty();
        other_set.add_ip_range(ip_range("10.0.0.0-10.0.0.2"));
        other_set.add_ip_range(ip_prefix("192.168.0.0/16").range);

        let mut expected_remaining = IpResourceSet::empty();
        expected_remaining.add_ip_range(ip_range("10.0.0.3-10.0.0.255"));
        expected_remaining.add_ip_range(ip_prefix("2001:DB8::/32").range);

        set.remove_ip_resource_set(&other_set);

        assert_eq!(set, expected_remaining);
    }

    #[test]
    fn test_ip_resource_set_serde() {
        let mut set = IpResourceSet::empty();
        set.add_ip_range(ip_range("10.0.0.0-10.0.0.255"));
        set.add_ip_range(ip_prefix("192.168.0.0/16").range);
        set.add_ip_range(ip_prefix("2001:DB8::/32").range);

        let json = serde_json::to_string(&set).unwrap();

        let set_deserialized: IpResourceSet = serde_json::from_str(&json).unwrap();

        assert_eq!(set, set_deserialized)
    }

    #[test]
    fn test_ip_range_tree() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct TypeWithRange {
            asn: u32,
            prefix: IpRange,
            max_length: u8,
        }

        impl AsRef<IpRange> for TypeWithRange {
            fn as_ref(&self) -> &IpRange {
                &self.prefix
            }
        }

        let vrps = vec![
            TypeWithRange {
                asn: 0,
                prefix: ip_range("10.0.0.0-10.0.0.255"),
                max_length: 24,
            },
            TypeWithRange {
                asn: 2,
                prefix: ip_range("10.0.0.0-10.0.0.255"),
                max_length: 24,
            },
            TypeWithRange {
                asn: 0,
                prefix: ip_range("10.0.0.0-10.0.1.255"),
                max_length: 24,
            },
            TypeWithRange {
                asn: 0,
                prefix: ip_range("10.0.2.0-10.0.3.255"),
                max_length: 24,
            },
        ];

        let mut builder = IpRangeTreeBuilder::empty();
        for vrp in vrps {
            builder.add(vrp);
        }
        let tree = builder.build();

        let search = ip_range("10.0.0.0-10.0.1.255");

        let matches = tree.matching_or_more_specific(&search);
        assert_eq!(3, matches.len());

        let search = ip_range("10.0.0.0-10.0.0.255");
        let matches = tree.matching_or_more_specific(&search);
        assert_eq!(2, matches.len());

        let search = ip_range("10.0.2.0-10.0.3.255");
        let matches = tree.matching_or_more_specific(&search);
        assert_eq!(1, matches.len());

        let search = ip_range("10.0.0.0-10.0.0.2");
        let matches = tree.matching_or_less_specific(&search);
        assert_eq!(3, matches.len());
    }

    #[test]
    fn test_ip_prefix_length() {
        assert_eq!(ip_prefix("192.168.0.0/16").nr_of_ips(), 65536);
        assert_eq!(ip_prefix("192.168.0.0/24").nr_of_ips(), 256);
        assert_eq!(ip_prefix("192.168.0.0/32").nr_of_ips(), 1);
        assert_eq!(ip_prefix("2001:db8::/120").nr_of_ips(), 256);
        assert_eq!(ip_prefix("2001:db8::/128").nr_of_ips(), 1);
    }
}
