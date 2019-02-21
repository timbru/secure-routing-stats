//! Parse ROAs.csv
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::BufRead;
use std::num::ParseIntError;
use std::path::PathBuf;
use std::str::FromStr;
use crate::ip::Asn;
use crate::ip::IpNetError;
use crate::ip::IpPrefix;
use crate::ip::IpRange;
use crate::ip::IpRangeError;
use crate::ip::IpRangeTree;
use crate::ip::IpRangeTreeBuilder;
use crate::ip::ToIpRange;


//------------ ValidatedRoaPrefix --------------------------------------------

#[derive(Clone, Debug)]
pub struct ValidatedRoaPrefix {
    asn: Asn,
    prefix: IpPrefix,
    max_length: u8
}

impl ToIpRange for ValidatedRoaPrefix {
    fn to_ip_range(&self) -> &IpRange {
        self.prefix.as_ref()
    }
}

impl ValidatedRoaPrefix {
    fn from_line(line: &str) -> Result<Self, Error> {
        let line = line.replace("\"", "");
        let mut values = line.split(',');

        let asn_str = values.next().ok_or(Error::ParseError)?;
        let asn = u32::from_str(&asn_str.replace("AS", ""))?;

        let prefix_str = values.next().ok_or(Error::ParseError)?;
        let prefix = IpPrefix::from_str(prefix_str)?;

        let length_str = values.next().ok_or(Error::ParseError)?;
        let max_length = u8::from_str(length_str)?;

        Ok(ValidatedRoaPrefix { asn, prefix, max_length })
    }
}


//------------ Roas ----------------------------------------------------------

pub type Roas = IpRangeTree<ValidatedRoaPrefix>;

impl Roas {
    pub fn from_file(path: &PathBuf) -> Result<Self, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut builder = IpRangeTreeBuilder::empty();

        // So that we can make an iterator of ValidatedRoaPrefix
        // and use it to construct the IntervalTree
        for lres in reader.lines() {
            let line = lres?;
            if line.starts_with("\"ASN\"") {
                continue
            }
            let vrp = ValidatedRoaPrefix::from_line(&line)?;
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

    #[display(fmt = "Error parsing ROAs.csv")]
    ParseError,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Error::IoError(e) }
}

impl From<IpRangeError> for Error {
    fn from(_e: IpRangeError) -> Self { Error::ParseError }
}

impl From<IpNetError> for Error {
    fn from(_e: IpNetError) -> Self { Error::ParseError }
}

impl From<ParseIntError> for Error {
    fn from(_e: ParseIntError) -> Self { Error::ParseError }
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








