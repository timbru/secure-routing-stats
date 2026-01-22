//! Handle NRO/RIR delegations

use std::fmt;
use std::fmt::Display;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::num::ParseIntError;
use std::path::Path;
use std::str::FromStr;

use intervaltree::IntervalTree;

use crate::inputs::{
    asn::{Asn, AsnError, AsnRange},
    ip::{
        IpAddress, IpAddressError, IpPrefix, IpPrefixError, IpRange,
        IpRangeError, IpRangeTree, IpRangeTreeBuilder,
    },
};

//------------ Registry -----------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Registry {
    Iana,
    Afrinic,
    Apnic,
    Arin,
    Lacnic,
    RipeNcc,
}

impl FromStr for Registry {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "iana" => Ok(Registry::Iana),
            "afrinic" => Ok(Registry::Afrinic),
            "apnic" => Ok(Registry::Apnic),
            "arin" => Ok(Registry::Arin),
            "lacnic" => Ok(Registry::Lacnic),
            "ripencc" => Ok(Registry::RipeNcc),
            r => Err(Error::parse_error(format!("unknown registry: {}", r))),
        }
    }
}

impl fmt::Display for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Registry::Iana => write!(f, "iana"),
            Registry::Afrinic => write!(f, "afrinic"),
            Registry::Apnic => write!(f, "apnic"),
            Registry::Arin => write!(f, "arin"),
            Registry::Lacnic => write!(f, "lacnic"),
            Registry::RipeNcc => write!(f, "ripencc"),
        }
    }
}

//------------ Region --------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Region {
    World,
    Registry(Registry),
    Country(String),
}

impl Region {
    pub fn is_country(&self) -> bool {
        matches!(self, Region::Registry(_))
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Region::World => write!(f, "world"),
            Region::Registry(registry) => registry.fmt(f),
            Region::Country(country) => write!(f, "{country}"),
        }
    }
}

//------------ DelegationState -----------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DelegationState {
    IANAPOOL,
    IETF,
    AVAILABLE,
    ASSIGNED,
    RESERVED,
}

impl FromStr for DelegationState {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ianapool" => Ok(DelegationState::IANAPOOL),
            "ietf" => Ok(DelegationState::IETF),
            "available" => Ok(DelegationState::AVAILABLE),
            "assigned" => Ok(DelegationState::ASSIGNED),
            "allocated" => Ok(DelegationState::ASSIGNED),
            "reserved" => Ok(DelegationState::RESERVED),
            s => Err(Error::parse_error(format!("Unknown state: {}", s))),
        }
    }
}

//------------ IpDelegation -------------------------------------------------

#[derive(Clone, Debug)]
pub struct IpDelegation {
    reg: Registry,
    cc: String,
    range: IpRange,
    state: DelegationState,
}

impl IpDelegation {
    pub fn reg(&self) -> &Registry {
        &self.reg
    }
    pub fn cc(&self) -> &str {
        &self.cc
    }
    pub fn range(&self) -> &IpRange {
        &self.range
    }
    pub fn state(&self) -> &DelegationState {
        &self.state
    }
}

impl IpDelegation {
    fn from_csv_line(s: &str) -> Result<Option<Self>, Error> {
        if s.starts_with("prefix") {
            return Ok(None);
        }

        let mut values = s.split(',');

        let prefix =
            values.next().ok_or_else(|| Error::missing("prefix", s))?;
        let rir = values.next().ok_or_else(|| Error::missing("rir", s))?;
        let _date_str =
            values.next().ok_or_else(|| Error::missing("date", s))?;
        let cc_str = values.next().ok_or_else(|| Error::missing("cc", s))?;
        let state_str =
            values.next().ok_or_else(|| Error::missing("state", s))?;

        let reg = Registry::from_str(rir)?;
        let cc = cc_str.to_string();
        let range: IpRange = IpPrefix::from_str(prefix)?.into();
        let state = DelegationState::from_str(state_str)?;

        Ok(Some(IpDelegation {
            reg,
            cc,
            range,
            state,
        }))
    }

    fn from_nro_line(s: &str) -> Result<Option<Self>, Error> {
        if s.contains("nro|") || s.contains("|asn|") {
            Ok(None)
        } else {
            let mut values = s.split('|');

            let reg_str =
                values.next().ok_or_else(|| Error::missing("rir", s))?;
            let cc_str =
                values.next().ok_or_else(|| Error::missing("cc", s))?;
            let inr_type_str =
                values.next().ok_or_else(|| Error::missing("type", s))?;
            let min_str =
                values.next().ok_or_else(|| Error::missing("min", s))?;
            let amount_str =
                values.next().ok_or_else(|| Error::missing("amount", s))?;
            let _date_str =
                values.next().ok_or_else(|| Error::missing("date", s))?;
            let state_str =
                values.next().ok_or_else(|| Error::missing("state", s))?;

            if inr_type_str != "ipv4" && inr_type_str != "ipv6" {
                Err(Error::parse_error("unsupported inr type"))
            } else {
                let reg = Registry::from_str(reg_str)?;
                let cc = cc_str.to_string();
                let min = IpAddress::from_str(min_str)?;
                let number = u128::from_str(amount_str)?;
                let range = IpRange::from_min_and_number(min, number)?;
                let state = DelegationState::from_str(state_str)?;

                Ok(Some(IpDelegation {
                    reg,
                    cc,
                    range,
                    state,
                }))
            }
        }
    }
}

impl AsRef<IpRange> for IpDelegation {
    fn as_ref(&self) -> &IpRange {
        &self.range
    }
}

//------------ IpDelegations ------------------------------------------------

#[derive(Debug)]
pub struct IpDelegations {
    tree: IpRangeTree<IpDelegation>,
}

impl IpDelegations {
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let file = File::open(path).map_err(|_| Error::read_error(path))?;
        let reader = BufReader::new(file);

        let mut builder = IpRangeTreeBuilder::empty();

        for lres in reader.lines() {
            let line = lres.map_err(Error::parse_error)?;
            let path_str = path.to_string_lossy().to_string();

            if path_str.ends_with(".csv") {
                if let Some(del) = IpDelegation::from_csv_line(&line)? {
                    builder.add(del);
                }
            } else if let Some(del) = IpDelegation::from_nro_line(&line)? {
                builder.add(del);
            }
        }

        Ok(IpDelegations {
            tree: builder.build(),
        })
    }

    pub fn find_cc(&self, range: &IpRange) -> &str {
        let matching = self.tree.matching_or_less_specific(range);
        match matching.first() {
            Some(delegation) => delegation.cc(),
            None => "XX",
        }
    }
}

//------------ AsnDelegation ------------------------------------------------

#[derive(Clone, Debug)]
pub struct AsnDelegation {
    registry: Registry,
    country_code: String,
    range: AsnRange,
    state: DelegationState,
}

impl AsnDelegation {
    pub fn registry(&self) -> Region {
        Region::Registry(self.registry)
    }

    pub fn country(&self) -> Region {
        Region::Country(self.country_code.clone())
    }

    pub fn country_code(&self) -> &String {
        &self.country_code
    }

    pub fn range(&self) -> AsnRange {
        self.range
    }

    pub fn state(&self) -> &DelegationState {
        &self.state
    }
}

impl AsnDelegation {
    /// Convert this to a range compatible with intervaltree
    pub fn range_for_intervaltree(&self) -> std::ops::Range<u32> {
        self.range.range_for_intervaltree()
    }

    /// Return assigned ASNs only
    fn from_nro_line(s: &str) -> Result<Option<Self>, Error> {
        if s.contains("nro|") || !s.contains("|asn|") {
            Ok(None)
        } else {
            let mut values = s.split('|');

            let reg_str =
                values.next().ok_or_else(|| Error::missing("rir", s))?;
            let cc_str =
                values.next().ok_or_else(|| Error::missing("cc", s))?;
            let inr_type_str =
                values.next().ok_or_else(|| Error::missing("type", s))?;
            let min_str =
                values.next().ok_or_else(|| Error::missing("min", s))?;
            let amount_str =
                values.next().ok_or_else(|| Error::missing("amount", s))?;
            let _date_str =
                values.next().ok_or_else(|| Error::missing("date", s))?;
            let state_str =
                values.next().ok_or_else(|| Error::missing("state", s))?;

            if inr_type_str != "asn" {
                Err(Error::parse_error("unsupported inr type"))
            } else {
                let state = DelegationState::from_str(state_str)?;

                if state == DelegationState::ASSIGNED {
                    let reg = Registry::from_str(reg_str)?;
                    let cc = cc_str.to_string();
                    let min = Asn::from_str(min_str)?;
                    let number = u32::from_str(amount_str)?;
                    let max = Asn::from(number + min.as_ref() - 1);
                    let range = AsnRange::new(min, max);

                    Ok(Some(AsnDelegation {
                        registry: reg,
                        country_code: cc,
                        range,
                        state,
                    }))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

//------------ AsnDelegations -----------------------------------------------

/// Supports indexing and cheap matching of AsnRanges
#[derive(Debug)]
pub struct AsnDelegations {
    tree: IntervalTree<u32, AsnDelegation>,
}

impl AsnDelegations {
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let file = File::open(path).map_err(|_| Error::read_error(path))?;
        let reader = BufReader::new(file);

        let mut delegations = Vec::new();

        for line_res in reader.lines() {
            let line = line_res.map_err(Error::parse_error)?;

            if let Some(delegation) = AsnDelegation::from_nro_line(&line)? {
                delegations.push(delegation);
            }
        }

        Ok(AsnDelegations::build(delegations))
    }

    pub fn build(delegations: Vec<AsnDelegation>) -> Self {
        let tree = delegations
            .into_iter()
            .map(|delegation| {
                (delegation.range_for_intervaltree(), delegation)
            })
            .collect();

        Self { tree }
    }

    /// Finds the matching delegation for a given ASN
    ///
    /// Note that in principle there should not be any overlaps in ASN
    /// delegations. If this happens there is an issue with the delegations
    /// input file. However, if this should happen this function just returns
    /// the first match, rather than erroring out or panicking.
    ///
    /// If there is no matching delegation, then we return None.
    pub fn matching(&self, asn: &Asn) -> Option<&AsnDelegation> {
        self.tree.query_point(asn.into()).next().map(|el| &el.value)
    }

    /// Gets all delegations (unsorted)
    pub fn all(&self) -> Vec<&AsnDelegation> {
        self.tree.iter().map(|e| &e.value).collect()
    }
}

//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Cannot read file: {}", _0)]
    CannotRead(String),

    #[display(fmt = "Missing column {} in line: {}", _0, _1)]
    MissingColumn(String, String),

    #[display(fmt = "Error parsing delegates-extended: {}", _0)]
    ParseError(String),
}

impl Error {
    fn read_error(path: &Path) -> Self {
        Error::CannotRead(path.to_string_lossy().to_string())
    }
    fn parse_error(e: impl Display) -> Self {
        Error::ParseError(format!("{}", e))
    }
    fn missing(c: &str, l: &str) -> Self {
        Error::MissingColumn(c.to_string(), l.to_string())
    }
}

impl From<AsnError> for Error {
    fn from(e: AsnError) -> Self {
        Self::parse_error(e)
    }
}

impl From<IpRangeError> for Error {
    fn from(e: IpRangeError) -> Self {
        Self::parse_error(e)
    }
}

impl From<IpAddressError> for Error {
    fn from(e: IpAddressError) -> Self {
        Self::parse_error(e)
    }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self {
        Self::parse_error(e)
    }
}

impl From<IpPrefixError> for Error {
    fn from(e: IpPrefixError) -> Self {
        Self::parse_error(e)
    }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn should_read_ip_delegation_from_file() {
        let path = PathBuf::from("test/20250112/delegated-extended.txt");
        IpDelegations::from_file(&path).unwrap();
    }

    #[test]
    fn should_read_asn_delegations_from_file() {
        let path = PathBuf::from("test/20250112/delegated-extended.txt");
        AsnDelegations::from_file(&path).unwrap();
    }
}
