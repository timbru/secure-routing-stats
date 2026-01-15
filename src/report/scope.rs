use std::str::FromStr;

use crate::inputs::{
    asn::{Asn, AsnError, AsnRange, AsnSet},
    ip::{
        IpAddress, IpAddressError, IpPrefix, IpPrefixError, IpRange,
        IpRangeError, IpResourceSet,
    },
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScopeQuery {
    pub scope: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScopeLimits {
    ips: IpResourceSet,
    asns: AsnSet,
}

impl FromStr for ScopeLimits {
    type Err = ScopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let line = s.replace(' ', "");
        let mut ips = IpResourceSet::empty();
        let mut asns = AsnSet::empty();

        for el in line.split(',') {
            if el.is_empty() {
                continue;
            } else if el.contains('.') || el.contains(':') {
                // IPv4 or IPv6
                if el.contains('-') {
                    let range = IpRange::from_str(el)?;
                    ips.add_ip_range(range);
                } else if el.contains('/') {
                    let prefix = IpPrefix::from_str(el)?;
                    ips.add_ip_range(prefix.into());
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
        ScopeLimits {
            ips: IpResourceSet::empty(),
            asns: AsnSet::empty(),
        }
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

    pub fn ips(&self) -> &IpResourceSet {
        &self.ips
    }

    pub fn asns(&self) -> &AsnSet {
        &self.asns
    }
}

//------------ ScopeError ---------------------------------------------------

#[derive(Debug, Display)]
pub enum ScopeError {
    #[display(fmt = "Can't parse: {}", _0)]
    ParseError(String),

    #[display(fmt = "{}", _0)]
    IpPrefixError(IpPrefixError),

    #[display(fmt = "{}", _0)]
    IpRangeError(IpRangeError),

    #[display(fmt = "{}", _0)]
    IpAddressError(IpAddressError),

    #[display(fmt = "{}", _0)]
    AsnError(AsnError),
}

impl From<IpPrefixError> for ScopeError {
    fn from(e: IpPrefixError) -> Self {
        ScopeError::IpPrefixError(e)
    }
}

impl From<IpRangeError> for ScopeError {
    fn from(e: IpRangeError) -> Self {
        ScopeError::IpRangeError(e)
    }
}

impl From<IpAddressError> for ScopeError {
    fn from(e: IpAddressError) -> Self {
        ScopeError::IpAddressError(e)
    }
}

impl From<AsnError> for ScopeError {
    fn from(e: AsnError) -> Self {
        ScopeError::AsnError(e)
    }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_parse() {
        let set = ScopeLimits::from_str("").unwrap();
        assert_eq!(ScopeLimits::empty(), set);

        let set = ScopeLimits::from_str("10.0.0.0/8").unwrap();
        assert_eq!(
            ScopeLimits::new(
                IpResourceSet::from_str("10.0.0.0/8").unwrap(),
                AsnSet::empty()
            ),
            set
        );
    }
}
