use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;
use std::cmp;

// https://tools.ietf.org/html/rfc4291#section-2.5.5
const IPV4_IN_IPV6: u128 = 0xffff_0000_0000;

#[derive(Debug, PartialEq)]
pub enum IpAddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, PartialEq)]
pub struct IpAddress {
    value: u128
}

impl fmt::Debug for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.ip_address_family() {
            IpAddressFamily::Ipv4 => {
                let b1 = (self.value & 0xff00_0000) >> 24;
                let b2 = (self.value & 0x00ff_0000) >> 16;
                let b3 = (self.value & 0x0000_ff00) >> 8;
                let b4 = self.value & 0x0000_00ff;
                write!(f, "{}.{}.{}.{}", b1, b2, b3, b4)
            }
            IpAddressFamily::Ipv6 => { write!(f, "{}", self.value)}
        }
    }
}

impl IpAddress {
    pub fn new(value: u128) -> Self {
        if value <= ::std::u32::MAX as u128 {
            IpAddress { value: IPV4_IN_IPV6 | value }
        } else {
            IpAddress { value }
        }
    }

    pub fn ip_address_family(&self) -> IpAddressFamily {
        match self.value & 0xffff_ffff_ffff_ffff_ffff_ffff_0000_0000 == IPV4_IN_IPV6 {
            true => { IpAddressFamily::Ipv4 }
            false => { IpAddressFamily::Ipv6 }
        }
    }

    fn parse_ipv4_address(s: &str) -> Result<Self, IpAddressError> {
        let mut result_value: u128 = 0;
        let mut groups = 0;
        for el in s.split('.') {
            groups += 1;
            let b_val = u8::from_str_radix(el, 10)?;
            result_value = result_value << 8;
            result_value += b_val as u128;
        }

        if groups != 4 {
            return Err(IpAddressError::WrongByteCount);
        }

        Ok(IpAddress::new(result_value))
    }
}

impl FromStr for IpAddress {
    type Err = IpAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('.') {
            IpAddress::parse_ipv4_address(s)
        } else if s.contains(':') {
            // As IPv6
            return Err(IpAddressError::NotImplemented);
        } else {
            return Err(IpAddressError::NotAnIpAddress);
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub struct IpRange {
    min: IpAddress,
    max: IpAddress,
}

impl IpRange {
    pub fn create(min: IpAddress, max: IpAddress) -> Result<Self, IpRangeError> {
        match min.value > max.value {
            true => { Err(IpRangeError::MinExceedsMax) }
            false => { Ok(IpRange { min, max }) }
        }
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
        let upper_bound = lower_bound | (1u128 << (128 - lead_in_common)) - 1;

        return self.min.value == lower_bound && self.max.value == upper_bound;
    }

    pub fn intersects(&self, other: IpRange) -> bool {
        (self.min.value <= other.min.value && self.max.value >= other.min.value) ||
            (self.min.value > other.min.value && self.min.value <= other.max.value)
    }

    pub fn contains(&self, other: IpRange) -> bool {
        self.min.value <= other.min.value && self.max.value >= other.max.value
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

#[derive(Debug)]
pub struct IpPrefix {
    base_address: IpAddress,
    length: u8,
}

impl FromStr for IpPrefix {
    type Err = IpNetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip_values: Vec<&str> = s.split('/').collect();

        if ip_values.iter().count() != 2 {
            return Err(IpNetError::InvalidSyntax);
        }

        let base_address = IpAddress::from_str(ip_values[0])?;
        let length: u8 = u8::from_str_radix(ip_values[1], 10)?;

        let full_length;
        match base_address.ip_address_family() {
            IpAddressFamily::Ipv4 => { full_length = length + 96; }
            IpAddressFamily::Ipv6 => { full_length = length; }
        };

        if full_length > 128 || full_length < (128 - base_address.value.trailing_zeros() as u8) {
            return Err(IpNetError::InvalidPrefixLength);
        }

        Ok(IpPrefix { base_address, length })
    }
}

#[derive(Debug)]
pub enum IpRangeOrPrefix {
    IpRange(IpRange),
    IpPrefix(IpPrefix),
}

#[derive(Debug)]
pub struct IpResourceSet {
    included: Vec<IpRange>
}

impl IpResourceSet {
    pub fn new() -> Self {
        let inc: Vec<IpRange> = vec![];
        IpResourceSet { included: inc }
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


#[derive(Debug, Fail)]
pub enum IpAddressError {
    #[fail(display = "Parse error: {}", _0)]
    ParseError(ParseIntError),

    #[fail(display = "Wrong number of bytes for IP address")]
    WrongByteCount,

    #[fail(display = "Pattern doesn't match IPv4 or IPv6")]
    NotAnIpAddress,

    #[fail(display = "Not Implemented")]
    NotImplemented,
}

impl From<ParseIntError> for IpAddressError {
    fn from(e: ParseIntError) -> IpAddressError {
        IpAddressError::ParseError(e)
    }
}


#[derive(Debug, Fail)]
pub enum IpRangeError {
    #[fail(display = "Minimum value exceeds maximum value")]
    MinExceedsMax,

    #[fail(display = "Expected two IP addresses separated by '-' and no whitespace")]
    MustUseDashNotation,

    #[fail(display = "Contains invalid IP address: {}", _0)]
    ContainsInvalidIpAddress(IpAddressError),
}

impl From<IpAddressError> for IpRangeError {
    fn from(e: IpAddressError) -> IpRangeError {
        IpRangeError::ContainsInvalidIpAddress(e)
    }
}


#[derive(Debug, Fail)]
pub enum IpNetError {
    #[fail(display = "Invalid syntax. Expect: address/length")]
    InvalidSyntax,

    #[fail(display = "Invalid prefix length")]
    InvalidPrefixLength,

    #[fail(display = "Base address invalid: {}", _0)]
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
    fn test_rang_invalid_if_min_bigger_than_max() {
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

        let mut set = IpResourceSet::new();
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
        let mut set = IpResourceSet::new();
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
}

