//! Validated RPKI Stats

use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display},
    fs::File,
    path::Path,
};

use chrono::{DateTime, Utc};

use crate::{
    inputs::{
        asn::Asn,
        ip::{IpPrefix, IpRange, IpRangeTree, IpRangeTreeBuilder},
        routinator::RoutinatorStatsJson,
    },
    report::scope::ScopeLimits,
};

//------------ RpkiStats ----------------------------------------------------

/// Validated RPKI Stats
///
/// For now, this is built using routinator style JSON as input,
/// but this can support CCR in future.
#[derive(Debug)]
pub struct RpkiStats {
    #[allow(dead_code)]
    generated: DateTime<Utc>,
    vrps: Vrps,
    aspas: ValidatedAspas,
}

impl RpkiStats {
    pub fn from_routinator_file(path: &Path) -> Result<Self, Error> {
        let file = File::open(path).map_err(|_| Error::read_error(path))?;

        serde_json::from_reader::<File, RoutinatorStatsJson>(file)
            .map(|routinator| routinator.into())
            .map_err(Error::parse_error)
    }

    pub fn vrps(&self) -> &Vrps {
        &self.vrps
    }

    pub fn aspas(&self) -> &ValidatedAspas {
        &self.aspas
    }
}

impl From<RoutinatorStatsJson> for RpkiStats {
    fn from(routinator: RoutinatorStatsJson) -> Self {
        let generated = DateTime::from_timestamp(routinator.metadata.generated, 0).unwrap();

        let payloads: Vec<ValidatedRoaPayload> = routinator
            .roas
            .into_iter()
            .map(|roa| ValidatedRoaPayload::new(roa.asn, roa.prefix, roa.max_length))
            .collect();

        let vrps = Vrps::from_payloads(payloads);

        let mut aspas = ValidatedAspas::new();
        for aspa in routinator.aspas.into_iter() {
            let entry = aspas.entry(aspa.customer).or_default();
            for provider in aspa.providers {
                entry.insert(provider);
            }
        }

        RpkiStats {
            generated,
            vrps,
            aspas,
        }
    }
}

//------------ ValidatedRoaPrefix --------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct ValidatedRoaPayload {
    asn: Asn,
    prefix: IpPrefix,
    max_length: u8,
}

impl ValidatedRoaPayload {
    pub fn new(asn: Asn, prefix: IpPrefix, max_length: u8) -> Self {
        ValidatedRoaPayload {
            asn,
            prefix,
            max_length,
        }
    }

    pub fn asn(&self) -> Asn {
        self.asn
    }

    pub fn prefix(&self) -> &IpPrefix {
        &self.prefix
    }

    pub fn max_length(&self) -> u8 {
        self.max_length
    }

    /// Return the number of most specific allowed
    /// announcements that would be expected for this
    /// VRP to not be "too specific", i.e. we expect
    /// that all of these announcements are seen.
    ///
    /// We do not care however in case all most specific
    /// announcements are seen, but not all less specific
    /// but still allowed annoucements are seen.
    pub fn nr_most_specific_announcements(&self) -> u128 {
        let nr_bytes = self.max_length - self.prefix.length();
        if nr_bytes >= 128 {
            // this should never happen, but there may be dragons in
            // the input.
            u128::MAX
        } else {
            1_u128 << nr_bytes
        }
    }
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

impl fmt::Display for ValidatedRoaPayload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "AS: {}, Prefix: {}, Max Length: {}",
            self.asn, self.prefix, self.max_length
        )
    }
}

//------------ Vrps ----------------------------------------------------------

#[derive(Debug)]
pub struct Vrps {
    tree: IpRangeTree<ValidatedRoaPayload>,
}

impl Vrps {
    pub fn from_payloads(payloads: Vec<ValidatedRoaPayload>) -> Self {
        let mut builder = IpRangeTreeBuilder::empty();

        for vrp in payloads {
            builder.add(vrp);
        }

        Vrps {
            tree: builder.build(),
        }
    }

    pub fn in_scope(&self, scope: &ScopeLimits) -> Vec<&ValidatedRoaPayload> {
        let mut vrps = if scope.limits_ips() {
            let set = scope.ips();
            set.ranges()
                .iter()
                .flat_map(|range| self.contained_by(range))
                .collect()
        } else {
            self.all()
        };

        if scope.limits_asns() {
            let set = scope.asns();
            vrps.retain(|vrp| set.contains(vrp.asn()))
        }

        vrps
    }

    pub fn all(&self) -> Vec<&ValidatedRoaPayload> {
        self.tree.all()
    }

    pub fn containing(&self, range: &IpRange) -> Vec<&ValidatedRoaPayload> {
        self.tree.matching_or_less_specific(range)
    }

    pub fn contained_by(&self, range: &IpRange) -> Vec<&ValidatedRoaPayload> {
        self.tree.matching_or_more_specific(range)
    }
}

//------------ ValidatedAspas ------------------------------------------------

pub type ValidatedAspas = HashMap<Asn, HashSet<Asn>>;

//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Cannot read file: {}", _0)]
    CannotRead(String),

    #[display(fmt = "Error parsing JSON: {}", _0)]
    ParseError(String),
}

impl Error {
    fn read_error(path: &Path) -> Self {
        Error::CannotRead(path.to_string_lossy().to_string())
    }
    fn parse_error(e: impl Display) -> Self {
        Error::ParseError(format!("{}", e))
    }
}

#[cfg(test)]
/// Parse a string like "AS65000, 192.168.0.0/20, 20"
/// panics when then wrong format is used.
pub fn vrp(s: &str) -> ValidatedRoaPayload {
    use std::str::FromStr;

    let line = s.replace('"', "");
    let line = line.replace(' ', "");
    let mut values = line.split(',');

    let asn_str = values.next().unwrap();
    let asn = Asn::from_str(asn_str).unwrap();

    let prefix_str = values.next().unwrap();
    let prefix = IpPrefix::from_str(prefix_str).unwrap();

    let length_str = values.next().unwrap();
    let max_length = u8::from_str(length_str).unwrap();

    ValidatedRoaPayload {
        asn,
        prefix,
        max_length,
    }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_detect_number_of_most_specific_announcements() {
        assert_eq!(
            vrp("AS65000, 192.168.0.0/20, 20").nr_most_specific_announcements(),
            1
        );
        assert_eq!(
            vrp("AS65000, 192.168.0.0/20, 24").nr_most_specific_announcements(),
            16
        );
    }
}
