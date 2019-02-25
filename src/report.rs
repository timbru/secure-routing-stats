//! Reporting of the stats found
use std::collections::HashMap;
use std::fmt::Write;
use validation::ValidatedAnnouncement;
use validation::ValidationState;

#[derive(Clone, Debug)]
pub struct CountryStat {
    routes_valid: usize,
    routes_inv_l: usize,
    routes_inv_a: usize,
    routes_not_f: usize,
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

    fn total(&self) -> usize {
        self.routes_valid + self.routes_inv_l + self.routes_inv_a + self.routes_not_f
    }

    fn covered(&self) -> usize {
        self.routes_valid + self.routes_inv_a + self.routes_inv_l
    }

    pub fn f_adoption(&self) -> f32 {
        (self.covered() * 10000 / self.total()) as f32 / 100.
    }

    pub fn f_valid(&self) -> f32 {
        (self.routes_valid * 10000 / self.total()) as f32 / 100.
    }

    pub fn f_quality(&self) -> Option<f32> {
        if self.covered() > 0 {
            Some((self.routes_valid * 10000 / self.covered()) as f32 / 100.)
        } else {
            None
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

    pub fn adoption_array(&self) -> String {
        let mut s = String::new();

        for cc in self.stats.keys() {
            let cs = &self.stats[&cc.to_string()];
            if cc != "all" {
                writeln!(&mut s, "          ['{}', {}],", cc, cs.f_adoption()).unwrap();
            }
        }
        s
    }

    pub fn valid_array(&self) -> String {
        let mut s = String::new();

        for cc in self.stats.keys() {
            let cs = &self.stats[&cc.to_string()];
            if cc != "all" {
                writeln!(&mut s, "          ['{}', {}],", cc, cs.f_valid()).unwrap();
            }
        }
        s
    }

    pub fn quality_array(&self) -> String {
        let mut s = String::new();

        for cc in self.stats.keys() {
            let cs = &self.stats[&cc.to_string()];
            if cc != "all" {
                if let Some(quality) = cs.f_quality() {
                    writeln!(&mut s, "          ['{}', {}],", cc, quality).unwrap();
                }
            }
        }
        s
    }
}


