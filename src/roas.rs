//! Parse ROAs.csv
use std::fmt::Display;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::BufRead;
use std::num::ParseIntError;
use std::path::PathBuf;
use std::str::FromStr;
use crate::ip::Asn;
use crate::ip::IpPrefixError;
use crate::ip::IpPrefix;
use crate::ip::IpRange;
use crate::ip::IpRangeTree;
use crate::ip::IpRangeTreeBuilder;


//------------ ValidatedRoaPrefix --------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct ValidatedRoaPayload {
    asn: Asn,
    prefix: IpPrefix,
    max_length: u8
}

impl ValidatedRoaPayload {
    pub fn asn(&self) -> &Asn { &self.asn }
    pub fn prefix(&self) -> &IpPrefix { &self.prefix }
    pub fn max_length(&self) -> u8 { self.max_length }
}

impl ValidatedRoaPayload {
    pub fn contains(&self, range: &IpRange) -> bool {
        self.prefix.as_ref().contains(&range.to_range())
    }
}


impl AsRef<IpRange> for ValidatedRoaPayload {
    fn as_ref(&self) -> &IpRange {
        self.prefix.as_ref()
    }
}

impl FromStr for ValidatedRoaPayload {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let line = s.replace("\"", "");
        let line = line.replace(" ", "");
        let mut values = line.split(',');

        let asn_str = values.next().ok_or(Error::MissingColumn)?;
        let asn = u32::from_str(&asn_str.replace("AS", ""))?;

        let prefix_str = values.next().ok_or(Error::MissingColumn)?;
        let prefix = IpPrefix::from_str(prefix_str)?;

        let length_str = values.next().ok_or(Error::MissingColumn)?;
        let max_length = u8::from_str(length_str)?;

        Ok(ValidatedRoaPayload { asn, prefix, max_length })
    }
}


//------------ Roas ----------------------------------------------------------

pub type Roas = IpRangeTree<ValidatedRoaPayload>;

impl Roas {
    pub fn from_file(path: &PathBuf) -> Result<Self, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut builder = IpRangeTreeBuilder::empty();

        for lres in reader.lines() {
            let line = lres?;
            let line = line.replace("\"", "");
            let line = line.replace(" ", "");
            if line.starts_with("ASN") {
                continue
            }
            let vrp = ValidatedRoaPayload::from_str(&line)?;
            builder.add(vrp);
        };

        Ok(builder.build())
    }
}


//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "Missing column in roas.csv")]
    MissingColumn,

    #[display(fmt = "Error parsing ROAs.csv: {}", _0)]
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

impl From<IpPrefixError> for Error {
    fn from(e: IpPrefixError) -> Self { Error::parse_error(e) }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self { Error::parse_error(e) }
}


//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_read_from_file() {
        let path = PathBuf::from("test/20181017/export-roa.csv");
        Roas::from_file(&path).unwrap();
    }
}








