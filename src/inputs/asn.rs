use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use serde::de;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;

//------------ Asn ----------------------------------------------------------
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Asn {
    val: u32,
}

impl Ord for Asn {
    fn cmp(&self, other: &Self) -> Ordering {
        self.val.cmp(&other.val)
    }
}

impl PartialOrd for Asn {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<u32> for Asn {
    fn as_ref(&self) -> &u32 {
        &self.val
    }
}

impl From<u32> for Asn {
    fn from(val: u32) -> Self {
        Asn { val }
    }
}

impl From<&Asn> for u32 {
    fn from(asn: &Asn) -> Self {
        asn.val
    }
}

impl FromStr for Asn {
    type Err = AsnError;

    fn from_str(s: &str) -> Result<Self, AsnError> {
        let val = s.to_lowercase().replace("as", "");
        let val = u32::from_str(&val).map_err(|_| AsnError::InvalidAsn)?;
        Ok(Asn { val })
    }
}

impl fmt::Display for Asn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AS{}", self.val)
    }
}

impl Serialize for Asn {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Asn {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = String::deserialize(d)?.to_ascii_lowercase();
        let stripped = string.strip_prefix("as").unwrap_or(&string);

        u32::from_str(stripped)
            .map(|val| Asn { val })
            .map_err(de::Error::custom)
    }
}

//------------ AsnRange ------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsnRange {
    min: Asn,
    max: Asn,
}

impl AsnRange {
    pub fn new(min: Asn, max: Asn) -> Self {
        AsnRange { min, max }
    }

    pub fn contains(&self, asn: Asn) -> bool {
        self.min <= asn && self.max >= asn
    }

    pub fn len(&self) -> u32 {
        self.max.val - self.min.val + 1
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// Convert this to a range compatible with intervaltree
    ///
    /// NOTE: intervaltree treats the max value as 'until'. Because of
    /// this we need to cheat a bit with regards to u32::MAX.
    pub fn range_for_intervaltree(&self) -> std::ops::Range<u32> {
        let start = self.min.val;
        let end = if self.max.val == u32::MAX {
            u32::MAX
        } else {
            self.max.val + 1
        };
        std::ops::Range { start, end }
    }
}

impl FromStr for AsnRange {
    type Err = AsnError;

    fn from_str(s: &str) -> Result<Self, AsnError> {
        let values: Vec<&str> = s.split('-').collect();

        if values.len() != 2 {
            return Err(AsnError::InvalidRange);
        }

        let min = Asn::from_str(values[0])?;
        let max = Asn::from_str(values[1])?;

        Ok(AsnRange { min, max })
    }
}

impl fmt::Display for AsnRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.min == self.max {
            write!(f, "{}", self.min)
        } else {
            write!(f, "{}-{}", self.min, self.max)
        }
    }
}

impl Serialize for AsnRange {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

//------------ AsnSet --------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsnSet {
    ranges: Vec<AsnRange>,
}

impl AsnSet {
    pub fn empty() -> Self {
        AsnSet { ranges: vec![] }
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn contains(&self, asn: Asn) -> bool {
        for range in &self.ranges {
            if range.contains(asn) {
                return true;
            }
        }
        false
    }

    pub fn add_range(&mut self, range: AsnRange) {
        self.ranges.push(range);
    }

    pub fn add_asn(&mut self, asn: Asn) {
        let range = AsnRange { min: asn, max: asn };
        self.ranges.push(range);
    }
}

impl FromStr for AsnSet {
    type Err = AsnError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let string = s.replace(' ', "");
        let mut elements = vec![];
        for el in string.split(',') {
            if el.contains('-') {
                let range = AsnRange::from_str(el)?;
                elements.push(range);
            } else {
                let asn = Asn::from_str(el)?;
                let range = AsnRange { min: asn, max: asn };
                elements.push(range);
            }
        }
        Ok(AsnSet { ranges: elements })
    }
}

impl fmt::Display for AsnSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let last_i = self.ranges.len() - 1;
        for i in 0..self.ranges.len() {
            self.ranges[i].fmt(f)?;
            if i != last_i {
                write!(f, ", ")?;
            }
        }

        Ok(())
    }
}

impl Serialize for AsnSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

//------------ AsnError ------------------------------------------------------

#[derive(Debug, Display)]
pub enum AsnError {
    #[display(fmt = "Expected comma separated ASNs or ASN ranges")]
    ExpectedCommaSeparated,

    #[display(fmt = "Invalid range. Expected something like: AS1-AS3")]
    InvalidRange,

    #[display(fmt = "Invalid ASN. Expected something like: 1 or AS1")]
    InvalidAsn,
}
