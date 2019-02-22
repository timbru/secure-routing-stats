//! Parse delegated extended stats
use std::str::FromStr;
use crate::ip::{
    IpRange
};
use std::io;
use ip::IpRangeTree;
use std::path::PathBuf;
use std::fs::File;
use std::io::BufReader;
use ip::IpRangeTreeBuilder;
use std::io::BufRead;
use ip::IpAddress;
use ip::IpRangeError;
use ip::IpAddressError;
use std::num::ParseIntError;
use std::fmt::Display;


//------------ Registry -----------------------------------------------------

#[derive(Clone, Debug)]
pub enum Registry {
    Iana,
    Afrinic,
    Apnic,
    Arin,
    Lacnic,
    RipeNcc
}

impl FromStr for Registry {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "iana"    => Ok(Registry::Iana),
            "afrinic" => Ok(Registry::Afrinic),
            "apnic"   => Ok(Registry::Apnic),
            "arin"    => Ok(Registry::Arin),
            "lacnic"  => Ok(Registry::Lacnic),
            "ripencc" => Ok(Registry::RipeNcc),
            r => Err(Error::parse_error(format!("unknown registry: {}", r)))
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
    RESERVED
}

impl FromStr for DelegationState {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ianapool"  => Ok(DelegationState::IANAPOOL),
            "ietf"      => Ok(DelegationState::IETF),
            "available" => Ok(DelegationState::AVAILABLE),
            "assigned"  => Ok(DelegationState::ASSIGNED),
            "reserved"  => Ok(DelegationState::RESERVED),
            s => Err(Error::parse_error(format!("Unknown state: {}", s)))
        }
    }
}


//------------ IpDelegation -------------------------------------------------

#[derive(Clone, Debug)]
pub struct IpDelegation {
    reg: Registry,
    cc: String,
    range: IpRange,
    state: DelegationState
}

impl IpDelegation {
    pub fn reg(&self) -> &Registry { &self.reg }
    pub fn cc(&self) -> &str { &self.cc }
    pub fn range(&self) -> &IpRange { &self.range }
    pub fn state(&self) -> &DelegationState { &self.state }
}

impl FromStr for IpDelegation {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut values = s.split('|');

        let reg_str = values.next().ok_or(Error::MissingColumn)?;
        let cc_str = values.next().ok_or(Error::MissingColumn)?;
        let inr_type_str = values.next().ok_or(Error::MissingColumn)?;
        let min_str = values.next().ok_or(Error::MissingColumn)?;
        let amount_str = values.next().ok_or(Error::MissingColumn)?;
        let _date_str = values.next().ok_or(Error::MissingColumn)?;
        let state_str = values.next().ok_or(Error::MissingColumn)?;

        if inr_type_str != "ipv4" && inr_type_str != "ipv6" {
            Err(Error::parse_error("unsupported inr type"))
        } else {
            let reg = Registry::from_str(reg_str)?;
            let cc = cc_str.to_string();
            let min = IpAddress::from_str(min_str)?;
            let number = u128::from_str(amount_str)?;
            let range = IpRange::from_min_and_number(min, number)?;
            let state = DelegationState::from_str(state_str)?;

            Ok(IpDelegation {reg, cc, range, state })
        }
    }
}

impl AsRef<IpRange> for IpDelegation {
    fn as_ref(&self) -> &IpRange {
        &self.range
    }
}


//------------ IpDelegations ------------------------------------------------

pub type IpDelegations = IpRangeTree<IpDelegation>;

impl IpDelegations {
    pub fn from_file(path: &PathBuf) -> Result<Self, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut builder = IpRangeTreeBuilder::empty();

        for lres in reader.lines() {
            let line = lres?;

            if line.contains("nro|") || line.contains("|asn|") {
                continue
            }

            let delegation = IpDelegation::from_str(&line)?;
            builder.add(delegation);
        };

        Ok(builder.build())
    }
}


//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "Missing column in delegated-extended")]
    MissingColumn,

    #[display(fmt = "Error parsing delegates-extended: {}", _0)]
    ParseError(String),
}

impl Error {
    fn parse_error(e: impl Display) -> Self {
        Error::ParseError(format!("{}", e))
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Error::IoError(e) }
}

impl From<IpRangeError> for Error {
    fn from(e: IpRangeError) -> Self { Self::parse_error(e) }
}

impl From<IpAddressError> for Error {
    fn from(e: IpAddressError) -> Self { Self::parse_error(e) }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self { Self::parse_error(e) }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_read_from_file() {
        let path = PathBuf::from("test/20181017/delegated-extended.txt");
        IpDelegations::from_file(&path).unwrap();
    }
}



