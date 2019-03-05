use crate::ip::AsnSet;
use crate::ip::IpResourceSet;
use std::str::FromStr;
use ip::IpAddress;
use ip::IpRange;
use ip::AsnRange;
use ip::Asn;
use ip::IpRangeError;
use ip::IpAddressError;
use ip::AsnError;

pub mod resources;
pub mod world;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScopeLimits {
    ips:  IpResourceSet,
    asns: AsnSet,
}

impl FromStr for ScopeLimits {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let line = s.replace(" ", "");
        let mut ips = IpResourceSet::empty();
        let mut asns = AsnSet::empty();

        for el in line.split(',') {
            if el.is_empty() {
                continue
            } else if el.contains('.') || el.contains(':') {
                // IPv4 or IPv6
                if el.contains('-') {
                    let range = IpRange::from_str(el)?;
                    ips.add_ip_range(range);
                } else {
                    let address = IpAddress::from_str(el)?;
                    ips.add_ip_address(address);
                }
            } else {
                // Must be ASN
                if el.contains('-') {
                    let range = AsnRange::from_str(el)?;
                    asns.add_range(range);
                } else {
                    let asn = Asn::from_str(el)?;
                    asns.add_asn(asn);
                }
            }
        }

        Ok(ScopeLimits { ips, asns })
    }
}


impl ScopeLimits {
    pub fn empty() -> Self {
        ScopeLimits { ips: IpResourceSet::empty(), asns: AsnSet::empty() }
    }
    pub fn new(ips: IpResourceSet, asns: AsnSet) -> Self {
        ScopeLimits { ips, asns }
    }

    pub fn limits_ips(&self) -> bool {
        !self.ips.is_empty()
    }

    pub fn limits_asns(&self) -> bool {
        !self.asns.is_empty()
    }

    pub fn ips(&self) -> &IpResourceSet{ &self.ips }

    pub fn asns(&self) -> &AsnSet { &self.asns }
}

//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Can't parse: {}", _0)]
    ParseError(String),

    #[display(fmt = "{}", _0)]
    IpRangeError(IpRangeError),

    #[display(fmt = "{}", _0)]
    IpAddressError(IpAddressError),

    #[display(fmt = "{}", _0)]
    AsnError(AsnError),
}

impl From<IpRangeError> for Error {
    fn from(e: IpRangeError) -> Self { Error::IpRangeError(e) }
}

impl From<IpAddressError> for Error {
    fn from(e: IpAddressError) -> Self { Error::IpAddressError(e) }
}

impl From<AsnError> for Error {
    fn from(e: AsnError) -> Self { Error::AsnError(e) }
}


//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_parse() {
        let set = ScopeLimits::from_str("").unwrap();
        assert_eq!(ScopeLimits::new(IpResourceSet::empty(), AsnSet::empty()), set);
    }

}