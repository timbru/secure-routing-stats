//! Support parsing announcements, for the moment only from RIS
//!
//! http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz

use std::io;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::num::ParseIntError;
use std::path::PathBuf;
use std::str::FromStr;
use crate::ip::Asn;
use crate::ip::IpPrefix;
use crate::ip::IpRange;
use crate::ip::IpRangeTree;
use crate::ip::IpRangeTreeBuilder;
use ip::IpNetError;


//------------ Announcement --------------------------------------------------

#[derive(Clone, Debug)]
pub struct Announcement {
    asn: Asn,
    prefix: IpPrefix
}

impl AsRef<IpRange> for Announcement {
    fn as_ref(&self) -> &IpRange {
        self.prefix.as_ref()
    }
}


//------------ RisAnnouncements ----------------------------------------------

pub type RisAnnouncements = IpRangeTree<Announcement>;

impl RisAnnouncements {
    pub fn from_file(path: &PathBuf) -> Result<Self, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut builder = IpRangeTreeBuilder::empty();

        for lres in reader.lines() {
            let line = lres?;
            if line.is_empty() || line.starts_with('%') {
                continue
            }

            let mut values = line.split_whitespace();

            let asn_str = values.next().ok_or(Error::ParseError)?;
            let prefix_str = values.next().ok_or(Error::ParseError)?;
            let peers = values.next().ok_or(Error::ParseError)?;

            if u32::from_str(peers)? <= 5 {
                continue
            }

            if asn_str.contains('{') {
                continue // assets not supported (not important here either)
            }

            let asn = Asn::from_str(asn_str)?;
            let prefix = IpPrefix::from_str(prefix_str)?;

            let ann = Announcement { asn, prefix };

            builder.add(ann);
        }

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
        let path = PathBuf::from("test/20181017/riswhoisdump.IPv4");
        let announcements = RisAnnouncements::from_file(&path).unwrap();

        let test_ann = Announcement {
            asn: 13335,
            prefix: IpPrefix::from_str("1.0.0.0/24").unwrap()
        };

        let matches = announcements.matching_or_more_specific(test_ann.as_ref());

        assert!(matches.len() > 0);
    }
}