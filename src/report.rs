//! Reporting of the stats found

use std::collections::HashMap;
use validation::ValidatedAnnouncement;
use validation::ValidationState;

#[derive(Clone, Debug)]
pub struct CountryStat {
    routes_valid: u32,
    routes_inv_l: u32,
    routes_inv_a: u32,
    routes_not_f: u32,
}

impl CountryStat {
    pub fn add(&mut self, ann: &ValidatedAnnouncement) {
        match ann.state() {
            ValidationState::Valid         => self.routes_valid += 1,
            ValidationState::InvalidLength => self.routes_inv_l += 1,
            ValidationState::InvalidAsn    => self.routes_inv_a += 1,
            ValidationState::NotFound      => self.routes_not_f += 1,
        }
    }
}

impl Default for CountryStat {
    fn default() -> Self {
        CountryStat {
            routes_valid: 0,
            routes_inv_l: 0,
            routes_inv_a: 0,
            routes_not_f: 0
        }
    }
}

#[derive(Clone, Debug)]
pub struct CountryStats {
    stats: HashMap<String, CountryStat>
}

impl Default for CountryStats {
    fn default() -> Self {
        CountryStats { stats: HashMap::new() }
    }
}

impl CountryStats {

    pub fn add(&mut self, ann: &ValidatedAnnouncement, cc: &str) {
        {
            let cc = cc.to_string();
            let stat = self.stats.entry(cc)
                .or_insert_with(CountryStat::default);
            stat.add(ann);
        }

        {
            let all_stat = self.stats.entry("all".to_string())
                .or_insert_with(CountryStat::default);
            all_stat.add(ann);
        }
    }
}


