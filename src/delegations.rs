//! Parse delegated extended stats
use crate::ip::{
    IpAddress, IpAddressError, IpRange, IpRangeError, IpRangeTree, IpRangeTreeBuilder,
};
use ip::{IpPrefix, IpPrefixError};
use std::fmt::Display;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::num::ParseIntError;
use std::path::Path;
use std::str::FromStr;

//------------ Registry -----------------------------------------------------

#[derive(Clone, Debug)]
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

//------------ DelegationState -----------------------------------------------

#[derive(Clone, Debug)]
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

        let prefix = values.next().ok_or_else(|| Error::missing("prefix", s))?;
        let rir = values.next().ok_or_else(|| Error::missing("rir", s))?;
        let _date_str = values.next().ok_or_else(|| Error::missing("date", s))?;
        let cc_str = values.next().ok_or_else(|| Error::missing("cc", s))?;
        let state_str = values.next().ok_or_else(|| Error::missing("state", s))?;

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

            let reg_str = values.next().ok_or_else(|| Error::missing("rir", s))?;
            let cc_str = values.next().ok_or_else(|| Error::missing("cc", s))?;
            let inr_type_str = values.next().ok_or_else(|| Error::missing("type", s))?;
            let min_str = values.next().ok_or_else(|| Error::missing("min", s))?;
            let amount_str = values.next().ok_or_else(|| Error::missing("amount", s))?;
            let _date_str = values.next().ok_or_else(|| Error::missing("date", s))?;
            let state_str = values.next().ok_or_else(|| Error::missing("state", s))?;

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
    fn should_read_from_file() {
        let path = PathBuf::from("test/20190304/delegated-extended.txt");
        IpDelegations::from_file(&path).unwrap();
    }

    #[test]
    fn read_csv() {
        let path = PathBuf::from("test/nrostats-20190101-v4.csv");
        IpDelegations::from_file(&path).unwrap();
    }
}
