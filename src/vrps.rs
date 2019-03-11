//! Parse ROAs.csv
use std::fmt;
use std::fmt::Display;
use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;
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


//------------ ValidatedRoaPrefix --------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct ValidatedRoaPayload {
    asn: Asn,
    prefix: IpPrefix,
    max_length: u8
}

impl ValidatedRoaPayload {
    pub fn asn(&self) -> Asn { self.asn }
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
        let asn = Asn::from_str(asn_str)?;

        let prefix_str = values.next().ok_or(Error::MissingColumn)?;
        let prefix = IpPrefix::from_str(prefix_str)?;

        let length_str = values.next().ok_or(Error::MissingColumn)?;
        let max_length = u8::from_str(length_str)?;

        Ok(ValidatedRoaPayload { asn, prefix, max_length })
    }
}

impl fmt::Display for ValidatedRoaPayload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "AS: {}, Prefix: {}, Max Length: {}",
            self.asn,
            self.prefix,
            self.max_length
        )
    }
}


//------------ Vrps ----------------------------------------------------------

#[derive(Debug)]
pub struct Vrps {
    tree: IpRangeTree<ValidatedRoaPayload>
}

impl Vrps {
    pub fn from_file(path: &PathBuf) -> Result<Self, Error> {
        let file = File::open(path).map_err(|_| Error::read_error(path))?;
        let reader = BufReader::new(file);

        let mut builder = IpRangeTreeBuilder::empty();

        for lres in reader.lines() {
            let line = lres.map_err(Error::parse_error)?;
            let line = line.replace("\"", "");
            let line = line.replace(" ", "");
            if line.starts_with("ASN") {
                continue
            }
            let vrp = ValidatedRoaPayload::from_str(&line)?;
            builder.add(vrp);
        };

        Ok(Vrps { tree: builder.build() })
    }

    pub fn in_scope(&self, scope: &ScopeLimits) -> Vec<&ValidatedRoaPayload> {
        let mut vrps = if scope.limits_ips() {
            let set = scope.ips();
            set.ranges().iter().flat_map(|range|
                self.contained_by(range)
            ).collect()
        } else {
            self.all()
        };

        if scope.limits_asns() {
            let set = scope.asns();
            vrps.retain(|vrp| set.contains(vrp.asn()))
        }

        vrps
    }


    pub fn all(&self) -> Vec<&ValidatedRoaPayload>{
        self.tree.all()
    }


    pub fn containing(&self, range: &IpRange) -> Vec<&ValidatedRoaPayload> {
        self.tree.matching_or_less_specific(range)
    }

    pub fn contained_by(&self, range: &IpRange) -> Vec<&ValidatedRoaPayload> {
        self.tree.matching_or_more_specific(range)
    }

}


//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Cannot read file: {}", _0)]
    CannotRead(String),

    #[display(fmt = "Missing column in roas.csv")]
    MissingColumn,

    #[display(fmt = "Error parsing ROAs.csv: {}", _0)]
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
        let path = PathBuf::from("test/20190304/vrps.csv");
        Vrps::from_file(&path).unwrap();
    }
}








