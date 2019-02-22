use crate::announcements::Announcement;
use crate::roas::ValidatedRoaPrefix;


//------------ ValidationState ----------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidationState {
    Valid,
    InvalidAsn,
    InvalidLength,
    NotFound
}


//------------ ValidatedAnnouncement -----------------------------------------

#[derive(Clone, Debug)]
pub struct ValidatedAnnouncement {
    announcement: Announcement,
    state: ValidationState
}

impl ValidatedAnnouncement {
    pub fn state(&self) -> &ValidationState {
        &self.state
    }

    fn derive_state(
        ann: &Announcement,
        vrps: &[&ValidatedRoaPrefix]
    ) -> ValidationState {
        let mut state = ValidationState::NotFound;

        for vrp in vrps {
            if vrp.contains(ann.as_ref()) {
                if vrp.asn() != ann.asn() {
                    if state != ValidationState::InvalidLength {
                        state = ValidationState::InvalidAsn;
                    }
                    continue
                }

                if ann.prefix().length() > vrp.max_length() {
                    state = ValidationState::InvalidLength;
                    continue
                }

                return ValidationState::Valid
            }
        }

        state
    }

    /// Creates a validated announcement for the referenced announcement, and
    /// validated roa prefixes. Takes references because this stuff is kept
    /// in immutable IntervalTree structures.
    pub fn create(ann: &Announcement, vrps: &[&ValidatedRoaPrefix]) -> Self {
        let state = Self::derive_state(ann, vrps);

        ValidatedAnnouncement {
            announcement: ann.clone(),
            state
        }
    }
}


//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use std::str::FromStr;

    fn vrp(s: &str) -> ValidatedRoaPrefix {
        ValidatedRoaPrefix::from_str(s).unwrap()
    }

    fn ann(s: &str) -> Announcement {
        Announcement::from_str(s).unwrap()
    }


    #[test]
    fn should_validate_announcement() {
        let ann = ann("65000, 192.168.0.0/20");

        let vrp_valid   = vrp("AS65000, 192.168.0.0/20, 20");
        let vrp_inv_len = vrp("AS65000, 192.168.0.0/16, 16");
        let vrp_inv_asn = vrp("AS65001, 192.168.0.0/16, 20");
        let vrp_not_fnd = vrp("AS65000, 192.168.0.0/24, 24");

        {
            // not found
            let validated = ValidatedAnnouncement::create(
                &ann,
                &[&vrp_not_fnd]
            );
            assert_eq!(&ValidationState::NotFound, validated.state());
        }

        {
            // invalid_len
            let validated = ValidatedAnnouncement::create(
                &ann,
                &[&vrp_inv_len, &vrp_inv_asn, &vrp_not_fnd]
            );
            assert_eq!(&ValidationState::InvalidLength, validated.state());
        }

        {
            // invalid asn
            let validated = ValidatedAnnouncement::create(
                &ann,
                &[&vrp_inv_asn, &vrp_not_fnd]
            );
            assert_eq!(&ValidationState::InvalidAsn, validated.state());
        }

        {
            // valid
            let validated = ValidatedAnnouncement::create(
                &ann,
                &[&vrp_inv_len, &vrp_inv_asn, &vrp_not_fnd, &vrp_valid]
            );
            assert_eq!(&ValidationState::Valid, validated.state());
        }
    }
}