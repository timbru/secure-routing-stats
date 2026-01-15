use std::fmt;

use crate::{
    inputs::{
        asn::Asn,
        ip::{IpPrefix, IpRange, IpRangeTree, IpRangeTreeBuilder},
    },
    report::scope::ScopeLimits,
};

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

    //     impl FromStr for ValidatedRoaPayload {
    //     type Err = Error;

    //     fn from_str(s: &str) -> Result<Self, Self::Err> {
    //     }
    // }
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

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_detect_number_of_most_specific_announcements() {
        assert_eq!(
            vrp("AS65000, 192.168.0.0/20, 20")
                .nr_most_specific_announcements(),
            1
        );
        assert_eq!(
            vrp("AS65000, 192.168.0.0/20, 24")
                .nr_most_specific_announcements(),
            16
        );
    }
}
