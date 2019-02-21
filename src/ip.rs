use std::cmp;
use std::collections::HashMap;
use std::fmt;
use std::net;
use std::num::ParseIntError;
use std::str::FromStr;
use std::ops::Range;
use intervaltree::IntervalTree;

// https://tools.ietf.org/html/rfc4291#section-2.5.5
const IPV4_IN_IPV6: u128 = 0xffff_0000_0000;
const IPV4_UNUSED: u128 = 0xffff_ffff_ffff_ffff_ffff_ffff_0000_0000;


//------------ Asn ----------------------------------------------------------

pub type Asn = u32;


//------------ IpAddressFamily -----------------------------------------------

#[derive(Debug, PartialEq)]
pub enum IpAddressFamily {
    Ipv4,
    Ipv6,
}


//------------ IpAddress -----------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
pub struct IpAddress {
    value: u128
}

impl IpAddress {
    /// Use with extreme prejudice. New IPv4 numbers should be specified as
    /// IPV4_IN_IPV6 | value
    fn new(value: u128) -> Self {
        IpAddress { value }
    }

    pub fn to_net_ipaddr(&self) -> net::IpAddr {
        match self.ip_address_family() {
            IpAddressFamily::Ipv4 => {
                net::IpAddr::V4(net::Ipv4Addr::from(self.value as u32))
            },
            IpAddressFamily::Ipv6 => {
                net::IpAddr::V6(net::Ipv6Addr::from(self.value))
            }
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
            Ok(IpAddress { value: IPV4_IN_IPV6 | value })
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

#[derive(Clone, Copy, PartialEq)]
pub struct IpRange {
    min: IpAddress,
    max: IpAddress,
}

impl IpRange {
    pub fn create(min: IpAddress, max: IpAddress) -> Result<Self, IpRangeError> {
        if min.value > max.value {
            Err(IpRangeError::MinExceedsMax)
        } else {
            Ok(IpRange { min, max })
        }
    }

    pub fn from_min_and_number(min: IpAddress, number: u128) -> Result<Self, IpRangeError> {
        let value = min.value + number - 1;
        let max = IpAddress{ value };
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
        let lower_bound = self.min.value & ::std::u128::MAX << (128 - lead_in_common);

        // Upper bound is then derived by keeping all the bits in common from
        // min value, and setting the remainder to 1s. This has to match the
        // value for self.max.value
        let upper_bound = lower_bound | ((1u128 << (128 - lead_in_common)) - 1);

        self.min.value == lower_bound && self.max.value == upper_bound
    }

    #[allow(clippy::nonminimal_bool)]
    pub fn intersects(&self, other: IpRange) -> bool {
        (self.min.value <= other.min.value && self.max.value >= other.min.value) ||
        (self.min.value > other.min.value && self.min.value <= other.max.value)
    }

    pub fn contains(&self, other: &Range<u128>) -> bool {
        self.min.value <= other.start && self.max.value >= other.end
    }

    pub fn is_contained_by(&self, other: &Range<u128>) -> bool {
        IpRange::from(other).contains(&self.to_range())
    }

    pub fn to_range(&self) -> std::ops::Range<u128> {
        std::ops::Range { start: self.min.value, end: self.max.value }
    }
}

impl fmt::Debug for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.min, self.max)
    }
}

impl FromStr for IpRange {
    type Err = IpRangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip_values: Vec<&str> = s.split('-').collect();

        if ip_values.iter().count() != 2 {
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


//------------ IpPrefix ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct IpPrefix {
    range: IpRange,
    length: u8,
}

impl FromStr for IpPrefix {
    type Err = IpNetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip_values: Vec<&str> = s.split('/').collect();

        if ip_values.iter().count() != 2 {
            return Err(IpNetError::InvalidSyntax);
        }

        let min = IpAddress::from_str(ip_values[0])?;
        let length: u8 = u8::from_str(ip_values[1])?;

        let full_length = match min.ip_address_family() {
            IpAddressFamily::Ipv4 => length + 96,
            IpAddressFamily::Ipv6 => length
        };

        if full_length > 128 || full_length < (128 - min.value.trailing_zeros() as u8) {
            return Err(IpNetError::InvalidPrefixLength);
        }

        let max_val = min.value | ((1u128 << (128 - full_length)) - 1);
        let max = IpAddress::new(max_val);

        let range = IpRange { min, max };

        Ok(IpPrefix { range, length })
    }
}

impl AsRef<IpRange> for IpPrefix {
    fn as_ref(&self) -> &IpRange {
        &self.range
    }
}


//------------ IpResourceSet -------------------------------------------------

#[derive(Debug)]
pub struct IpResourceSet {
    included: Vec<IpRange>
}

impl IpResourceSet {
    pub fn empty() -> Self {
        IpResourceSet { included: vec![] }
    }

    // Returns the intersecting IpRanges as the left return value, and non-intersecting as the right.
    fn partition_intersecting(&self, ip_range: IpRange) -> (Vec<IpRange>, Vec<IpRange>) {
        self.included.iter().partition(|ref i| i.intersects(ip_range))
    }

    pub fn add_ip_range(&mut self, ip_range: IpRange) {
        let (intersecting, mut keep) = self.partition_intersecting(ip_range);


        let mut min = ip_range.min.value;
        let mut max = ip_range.max.value;
        for e in intersecting.iter() {
            min = cmp::min(min, e.min.value);
            max = cmp::max(max, e.max.value);
        }

        let range_to_add = IpRange::create(IpAddress::new(min), IpAddress::new(max));

        keep.extend(range_to_add);

        self.included = keep;
    }

    pub fn remove_ip_range(&mut self, range_to_remove: IpRange) {
        let (intersecting, mut keep) = self.partition_intersecting(range_to_remove);

        for intersecting_range in intersecting.iter() {
            if range_to_remove.max.value < intersecting_range.max.value {
                // Something on the right should remain
                keep.extend(
                    IpRange::create(
                        IpAddress::new(range_to_remove.max.value + 1),
                        IpAddress::new(intersecting_range.max.value)));
            }

            if range_to_remove.min.value > intersecting_range.min.value {
                // Something on the left should remain
                keep.extend(
                    IpRange::create(
                        IpAddress::new(intersecting_range.min.value),
                        IpAddress::new(range_to_remove.min.value - 1)));
            }
        }

        self.included = keep;
    }
}


//------------ IpRangeTree --------------------------------------------------

pub struct IpRangeTree<V: ToIpRange> {
    tree: IntervalTree<u128, Vec<V>>
}

impl<V: ToIpRange> IpRangeTree<V> {
    pub fn new(tree: IntervalTree<u128, Vec<V>>) -> Self {
        IpRangeTree { tree }
    }

    pub fn matching_or_less_specific(&self, range: &IpRange) -> Vec<&V> {
        let mut res = vec![];
        for mut v in self.tree.query(range.to_range()) {
            if range.is_contained_by(&v.range) {
                for e in &v.value {
                    res.push(e)
                }
            }
        }
        res
    }

    pub fn matching_or_more_specific(&self, range: &IpRange) -> Vec<&V> {
        let mut res = vec![];
        for mut v in self.tree.query(range.to_range()) {
            if range.contains(&v.range) {
                for e in &v.value {
                    res.push(e)
                }
            }
        }
        res
    }
}

pub trait ToIpRange {
    fn to_ip_range(&self) -> &IpRange;
}

pub struct IpRangeTreeBuilder<V: ToIpRange> {
    values: HashMap<Range<u128>, Vec<V>>
}

impl<V: ToIpRange> IpRangeTreeBuilder<V> {
    pub fn empty() -> Self { IpRangeTreeBuilder { values: HashMap::new() }}

    pub fn add(&mut self, value: V) {
        let ip_range = value.to_ip_range().to_range();

        let entry = self.values.entry(ip_range).or_insert_with(|| vec![]);
        entry.push(value);
    }

    pub fn build(self) -> IpRangeTree<V> {
        let tree = self.values.into_iter().collect();
        IpRangeTree { tree }
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
pub enum IpNetError {
    #[display(fmt = "Invalid syntax. Expect: address/length")]
    InvalidSyntax,

    #[display(fmt = "Invalid prefix length")]
    InvalidPrefixLength,

    #[display(fmt = "Base address invalid: {}", _0)]
    InvalidBaseAddress(IpAddressError),
}

impl From<IpAddressError> for IpNetError {
    fn from(e: IpAddressError) -> IpNetError {
        IpNetError::InvalidBaseAddress(e)
    }
}

impl From<ParseIntError> for IpNetError {
    fn from(_: ParseIntError) -> IpNetError {
        IpNetError::InvalidPrefixLength
    }
}



//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_ipv4_from_string() {
        assert_eq!(IPV4_IN_IPV6 | 0, IpAddress::from_str("0.0.0.0").unwrap().value);
        assert_eq!(IPV4_IN_IPV6 | 255, IpAddress::from_str("0.0.0.255").unwrap().value);
        assert_eq!(IPV4_IN_IPV6 | 256, IpAddress::from_str("0.0.1.0").unwrap().value);
        assert_eq!(IPV4_IN_IPV6 | 65535, IpAddress::from_str("0.0.255.255").unwrap().value);
        assert_eq!(IPV4_IN_IPV6 | 65536, IpAddress::from_str("0.1.0.0").unwrap().value);
        assert_eq!(IPV4_IN_IPV6 | 16777216, IpAddress::from_str("1.0.0.0").unwrap().value);

        assert!(IpAddress::from_str("yadiyada").is_err());
        assert!(IpAddress::from_str("").is_err());
        assert!(IpAddress::from_str("1.1").is_err());
    }

    #[test]
    fn test_is_ipv4() {
        assert_eq!(IpAddressFamily::Ipv4, IpAddress::from_str("0.0.0.0").unwrap().ip_address_family());
        assert_eq!(IpAddressFamily::Ipv4, IpAddress::from_str("10.0.0.0").unwrap().ip_address_family());
        assert_eq!(IpAddressFamily::Ipv4, IpAddress::from_str("255.255.255.255").unwrap().ip_address_family());
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
        assert!(IpRange::from_str("10.0.0.0-10.0.255.255").unwrap().is_prefix());
        assert!(IpRange::from_str("10.0.0.0-10.1.255.255").unwrap().is_prefix());
        assert!(IpRange::from_str("0.0.0.0-1.255.255.255").unwrap().is_prefix());
        assert!(IpRange::from_str("2.0.0.0-3.255.255.255").unwrap().is_prefix());
        assert!(IpRange::from_str("0.0.0.0-3.255.255.255").unwrap().is_prefix());
        assert!(IpRange::from_str("4.0.0.0-5.255.255.255").unwrap().is_prefix());
        assert!(IpRange::from_str("4.0.0.0-4.0.0.0").unwrap().is_prefix());
        assert!(!IpRange::from_str("0.0.0.255-0.0.1.255").unwrap().is_prefix());
        assert!(!IpRange::from_str("2.0.0.0-5.255.255.255").unwrap().is_prefix());
        assert!(!IpRange::from_str("0.0.0.0-2.255.255.255").unwrap().is_prefix());
        assert!(!IpRange::from_str("10.0.0.0-10.0.255.254").unwrap().is_prefix());
        assert!(!IpRange::from_str("10.0.0.0-10.0.254.255").unwrap().is_prefix());
        assert!(!IpRange::from_str("0.0.0.128-0.0.1.127").unwrap().is_prefix());
    }

    #[test]
    fn test_range_from_start_and_number() {
        let range = IpRange::from_str("10.0.0.0-10.0.0.255").unwrap();
        let range_with_number = IpRange::from_min_and_number(
            IpAddress::from_str("10.0.0.0").unwrap(),
            256
        ).unwrap();

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
        let range = IpRange::from_str("10.0.0.0-10.0.0.255").unwrap();
        let intersecting_start = IpRange::from_str("9.0.0.0-10.0.0.0").unwrap();
        let intersecting_end = IpRange::from_str("10.0.0.255-10.1.0.0").unwrap();
        let exact_overlap = IpRange::from_str("10.0.0.0-10.0.0.255").unwrap();
        let more_specific = IpRange::from_str("10.0.0.0-10.0.0.255").unwrap();

        assert!(range.intersects(intersecting_start));
        assert!(range.intersects(intersecting_end));
        assert!(range.intersects(exact_overlap));
        assert!(range.intersects(more_specific));

        let below = IpRange::from_str("1.0.0.0-9.255.255.255").unwrap();
        let above = IpRange::from_str("10.0.1.0-19.255.255.255").unwrap();

        assert!(!range.intersects(below));
        assert!(!range.intersects(above));
    }

    #[test]
    fn test_ip_resource_set_functions() {
        let range = IpRange::from_str("10.0.0.0-10.0.0.255").unwrap();

        let mut set = IpResourceSet::empty();
        set.add_ip_range(range);

        assert_eq!(set.included, vec![range]);

        let intersecting_start = IpRange::from_str("9.0.0.0-10.0.0.0").unwrap();
        let expected_combined_range = IpRange::from_str("9.0.0.0-10.0.0.255").unwrap();
        set.add_ip_range(intersecting_start);
        assert_eq!(set.included, vec![expected_combined_range]);

        let other_range = IpRange::from_str("192.168.0.0-192.168.0.1").unwrap();
        set.add_ip_range(other_range);
        assert_eq!(set.included, vec![expected_combined_range, other_range]);
    }

    #[test]
    fn test_ip_resource_set_remove() {
        let range = IpRange::from_str("10.0.0.0-10.0.0.255").unwrap();
        let mut set = IpResourceSet::empty();
        set.add_ip_range(range);

        let intersecting_start = IpRange::from_str("9.0.0.0-10.0.0.0").unwrap();
        set.remove_ip_range(intersecting_start);
        assert_eq!(set.included, vec![IpRange::from_str("10.0.0.1-10.0.0.255").unwrap()]);

        let start_left_hand = IpRange::from_str("10.0.0.1-10.0.0.2").unwrap();
        set.remove_ip_range(start_left_hand);
        assert_eq!(set.included, vec![IpRange::from_str("10.0.0.3-10.0.0.255").unwrap()]);

        let middle = IpRange::from_str("10.0.0.10-10.0.0.11").unwrap();
        set.remove_ip_range(middle);
        assert_eq!(set.included,
                   vec![IpRange::from_str("10.0.0.12-10.0.0.255").unwrap(),
                        IpRange::from_str("10.0.0.3-10.0.0.9").unwrap()]);

        let exact_match = IpRange::from_str("10.0.0.3-10.0.0.9").unwrap();
        set.remove_ip_range(exact_match);
        assert_eq!(set.included, vec![IpRange::from_str("10.0.0.12-10.0.0.255").unwrap()]);

        let encompassing = IpRange::from_str("10.0.0.0-10.0.0.255").unwrap();
        set.remove_ip_range(encompassing);
        assert_eq!(set.included, vec![]);
    }

    #[test]
    fn test_ip_range_tree() {

        #[derive(Debug)]
        struct VRP {
            asn: u32,
            prefix: IpRange,
            max_length: u8
        }

        let vrps = vec![
            VRP { asn: 0, prefix: IpRange::from_str("10.0.0.0-10.0.0.255").unwrap(), max_length: 24 },
            VRP { asn: 2, prefix: IpRange::from_str("10.0.0.0-10.0.0.255").unwrap(), max_length: 24 },
            VRP { asn: 0, prefix: IpRange::from_str("10.0.0.0-10.0.1.255").unwrap(), max_length: 24 },
            VRP { asn: 0, prefix: IpRange::from_str("10.0.2.0-10.0.3.255").unwrap(), max_length: 24 },
        ];

        impl ToIpRange for VRP {
            fn to_ip_range(&self) -> &IpRange {
                &self.prefix
            }
        }

        let mut builder = IpRangeTreeBuilder::empty();
        for vrp in vrps {
            builder.add(vrp);
        }
        let tree = builder.build();

        let search = IpRange::from_str("10.0.0.0-10.0.1.255").unwrap();

        let matches = tree.matching_or_more_specific(&search);
        assert_eq!(3, matches.len());

        let search = IpRange::from_str("10.0.0.0-10.0.0.255").unwrap();
        let matches = tree.matching_or_more_specific(&search);
        assert_eq!(2, matches.len());

        let search = IpRange::from_str("10.0.2.0-10.0.3.255").unwrap();
        let matches = tree.matching_or_more_specific(&search);
        assert_eq!(1, matches.len());

        let search = IpRange::from_str("10.0.0.0-10.0.0.2").unwrap();
        let matches = tree.matching_or_less_specific(&search);
        assert_eq!(3, matches.len());
    }

}

