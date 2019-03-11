//! Support parsing announcements, for the moment only from RIS
//!
//! http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz

use std::fmt::Display;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::num::ParseIntError;
use std::path::PathBuf;
use std::str::FromStr;
use crate::ip::Asn;
use crate::ip::AsnError;
use crate::ip::IpPrefixError;
use crate::ip::IpPrefix;
use crate::ip::IpRange;
use crate::ip::IpRangeTree;
use crate::ip::IpRangeTreeBuilder;
use crate::report::ScopeLimits;


//------------ Announcement --------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct Announcement {
    asn: Asn,
    prefix: IpPrefix
}

impl Announcement {
    pub fn new(prefix: IpPrefix, asn: Asn) -> Self {
        Announcement { prefix, asn }
    }

    pub fn asn(&self) -> Asn { self.asn }
    pub fn prefix(&self) -> &IpPrefix { &self.prefix }
}

impl FromStr for Announcement {
    type Err = Error;

    /// Expects: "Asn, IpPrefix"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let line = s.replace(" ", ""); // strip whitespace
        let mut values = line.split(',');
        let asn_str = values.next().ok_or(Error::MissingColumn)?;
        let pfx_str = values.next().ok_or(Error::MissingColumn)?;
        let asn = Asn::from_str(asn_str)?;
        let prefix = IpPrefix::from_str(pfx_str)?;
        Ok(Announcement{ asn, prefix })
    }
}

impl AsRef<IpRange> for Announcement {
    fn as_ref(&self) -> &IpRange {
        self.prefix.as_ref()
    }
}


//------------ Announcements -------------------------------------------------

#[derive(Debug)]
pub struct Announcements {
    tree: IpRangeTree<Announcement>
}

impl Announcements {

    fn parse_ris_file(
        builder: &mut IpRangeTreeBuilder<Announcement>,
        path: &PathBuf
    ) -> Result<(), Error> {
        let file = File::open(path).map_err(|_| Error::read_error(path))?;
        let reader = BufReader::new(file);
        for lres in reader.lines() {
            let line = lres.map_err(Error::parse_error)?;
            if line.is_empty() || line.starts_with('%') {
                continue
            }

            let mut values = line.split_whitespace();

            let asn_str = values.next().ok_or(Error::MissingColumn)?;
            let prefix_str = values.next().ok_or(Error::MissingColumn)?;
            let peers = values.next().ok_or(Error::MissingColumn)?;

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
        Ok(())
    }

    pub fn from_ris(
        v4_path: &PathBuf,
        v6_path: &PathBuf
    ) -> Result<Self, Error> {
        let mut builder = IpRangeTreeBuilder::empty();

        Self::parse_ris_file(&mut builder, v4_path)?;
        Self::parse_ris_file(&mut builder, v6_path)?;

        Ok(Announcements { tree: builder.build() })
    }

    pub fn all(&self) -> Vec<&Announcement>{
        self.tree.all()
    }

    pub fn in_scope(&self, scope: &ScopeLimits) -> Vec<&Announcement> {
        let mut anns = if scope.limits_ips() {
            let ranges = scope.ips().ranges();
            ranges.iter().flat_map(|range|
                self.contained_by(range)
            ).collect()
        } else {
            self.all()
        };

        if scope.limits_asns() {
            let asn_set = &scope.asns();
            anns.retain(|ann| asn_set.contains(ann.asn()));
        }

        anns
    }

    /// Matches announcements that match the given range exactly, or which
    /// are more specific (i.e. the have a longer matching common part).
    pub fn contained_by(&self, range: &IpRange) -> Vec<&Announcement> {
        self.tree.matching_or_more_specific(range)
    }
}


//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Cannot read file: {}", _0)]
    CannotRead(String),

    #[display(fmt = "Missing column in announcements input")]
    MissingColumn,

    #[display(fmt = "Error parsing announcements: {}", _0)]
    ParseError(String),
}

impl Error {
    fn read_error(path: &PathBuf) -> Self {
        Error::CannotRead(path.to_string_lossy().to_string())
    }
    fn parse_error(e: impl Display) -> Self {
        Error::ParseError(format!("{}", e))
    }
}

impl From<IpPrefixError> for Error {
    fn from(e: IpPrefixError) -> Self { Error::parse_error(e) }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self { Error::parse_error(e) }
}

impl From<AsnError> for Error {
    fn from(e: AsnError) -> Self { Error::parse_error(e) }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_read_from_file() {
        let v4_path = PathBuf::from("test/20190304/riswhoisdump.IPv4");
        let v6_path = PathBuf::from("test/20190304/riswhoisdump.IPv6");
        let announcements = Announcements::from_ris(&v4_path, &v6_path).unwrap();

        let test_ann = Announcement {
            asn: Asn::from_str("AS13335").unwrap(),
            prefix: IpPrefix::from_str("1.0.0.0/24").unwrap()
        };

        let matches = announcements.contained_by(test_ann.as_ref());

        assert_eq!(matches.len(), 1);
    }
}