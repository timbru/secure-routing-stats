use std::num::ParseIntError;
use std::str::FromStr;

// Idea inspired by the IP implementation in Golang
const IPV4_IN_IPV6: u128 = 0xffff_0000_0000;

#[derive(Debug, PartialEq)]
pub enum IpAddressFamily {
    Ipv4,
    Ipv6
}

pub struct IpAddress {
    value: u128
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


pub struct IpRange {
    min: IpAddress,
    max: IpAddress,
}

impl IpRange {

    pub fn create(min: IpAddress, max: IpAddress) -> Result<Self, IpRangeError> {
        match min.value > max.value {
            true =>{ Err(IpRangeError::MinExceedsMax) }
            false => { Ok(IpRange{min, max}) }
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

#[derive(Debug, Fail)]
pub enum IpAddressError {

    #[fail(display="Parse error: {}", _0)]
    ParseError(ParseIntError),

    #[fail(display="Wrong number of bytes for IP address")]
    WrongByteCount,

    #[fail(display="Pattern doesn't match IPv4 or IPv6")]
    NotAnIpAddress,

    #[fail(display="Not Implemented")]
    NotImplemented
}

impl From<ParseIntError> for IpAddressError {
    fn from(e: ParseIntError) -> IpAddressError {
        IpAddressError::ParseError(e)
    }
}


#[derive(Debug, Fail)]
pub enum IpRangeError {

    #[fail(display="Minimum value exceeds maximum value")]
    MinExceedsMax,

    #[fail(display="Expected two IP addresses separated by '-' and no whitespace")]
    MustUseDashNotation,

    #[fail(display="Contains invalid IP address: {}", _0)]
    ContainsInvalidIpAddress(IpAddressError)
}

impl From<IpAddressError> for IpRangeError {
    fn from(e: IpAddressError) -> IpRangeError {
        IpRangeError::ContainsInvalidIpAddress(e)
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
        assert!(! IpRange::from_str("0.0.0.255-0.0.1.255").unwrap().is_prefix());
        assert!(! IpRange::from_str("2.0.0.0-5.255.255.255").unwrap().is_prefix());
        assert!(! IpRange::from_str("0.0.0.0-2.255.255.255").unwrap().is_prefix());
        assert!(! IpRange::from_str("10.0.0.0-10.0.255.254").unwrap().is_prefix());
        assert!(! IpRange::from_str("10.0.0.0-10.0.254.255").unwrap().is_prefix());
        assert!(! IpRange::from_str("0.0.0.128-0.0.1.127").unwrap().is_prefix());
    }


}

