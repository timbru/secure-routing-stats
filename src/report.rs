//! Reporting of the stats found
use std::collections::HashMap;
use std::fmt::Write;
use std::path::PathBuf;
use std::str::FromStr;
use clap::ArgMatches;
use crate::announcements::Announcement;
use crate::announcements::RisAnnouncements;
use crate::delegations::IpDelegation;
use crate::delegations::IpDelegations;
use crate::ip::IpRangeTree;
use crate::ip::IpResourceSet;
use crate::ip::IpRespourceSetError;
use crate::roas::Roas;
use crate::roas::ValidatedRoaPrefix;
use crate::validation::ValidatedAnnouncement;
use crate::validation::ValidationState;


//------------ CountryStat --------------------------------------------------

#[derive(Clone, Debug, Serialize)]
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


//------------ CountryStats -------------------------------------------------

/// This type keeps a map of country code to CountryStat.
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

    /// Adds a ValidatedAnnouncement to the stats for the given country code.
    /// Also adds this to the overall 'all' countries category.
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

    /// Returns an adoption array string of country codes to percentages of
    /// adoption for inclusion in the HTML output.
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

    /// Returns an adoption array string of country codes to percentages of
    /// valid announcements for inclusion in the HTML output.
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

    /// Returns an adoption array string of country codes to percentages of
    /// quality metrics, defined as valid/covered, for inclusion in the HTML
    /// output.
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

//------------ WorldStatsOpts -----------------------------------------------

/// Options for the WorldStatsReport
pub struct WorldStatsOpts {
    dump: PathBuf,
    roas: PathBuf,
    stats: PathBuf,
    format: WorldStatsFormat
}

impl WorldStatsOpts {
    pub fn parse(matches: &ArgMatches) -> Result<Self, Error> {

        let dump_file = matches.value_of("dump").unwrap();
        let dump = PathBuf::from(dump_file);

        let roas_file = matches.value_of("roas").unwrap();
        let roas = PathBuf::from(roas_file);

        let stats_file = matches.value_of("stats").unwrap();
        let stats = PathBuf::from(stats_file);

        let format = {
            if let Some(format) = matches.value_of("format") {
                match format {
                    "json" => WorldStatsFormat::Json,
                    "html" => WorldStatsFormat::Html,
                    f => return Err(Error::WithMessage(
                        format!("Unsupported format: {}", f)))
                }
            } else {
                WorldStatsFormat::Json
            }
        };

        Ok(WorldStatsOpts { dump, roas, stats, format })
    }
}


//------------ WorldStatsFormat ----------------------------------------------

/// Output format. The HTML uses the template in ['templates/world.html'].
pub enum WorldStatsFormat {
    Json,
    Html
}


//------------ WorldStatsReport ----------------------------------------------

/// This type is used to create reports on a per country basis. Can export to
/// json, or HTML using the template included in this source.
pub struct WorldStatsReport;

impl WorldStatsReport {

    pub fn execute(options: &WorldStatsOpts) -> Result<(), Error> {
        let announcements: IpRangeTree<Announcement> =
            RisAnnouncements::from_file(&options.dump).unwrap();

        let roas: IpRangeTree<ValidatedRoaPrefix> =
            Roas::from_file(&options.roas).unwrap();

        let delegations: IpRangeTree<IpDelegation> =
            IpDelegations::from_file(&options.stats).unwrap();


        let mut country_stats = CountryStats::default();

        for el in announcements.inner().iter() {
            for ann in el.value.iter() {

                let matching_roas = roas.matching_or_less_specific(ann.as_ref());
                let validated = ValidatedAnnouncement::create(ann, &matching_roas);

                let matching_delegations = delegations.matching_or_less_specific(ann.as_ref());

                let cc = match matching_delegations.first() {
                    Some(delegation) => &delegation.cc(),
                    None => "XX"
                };

                country_stats.add(&validated, cc);
            }
        }

        match options.format {
            WorldStatsFormat::Json => Self::json(&country_stats),
            WorldStatsFormat::Html => Self::html(&country_stats)
        }

        Ok(())
    }

    fn json(stats: &CountryStats) {
        println!("{:?}", stats);
    }

    fn html(stats: &CountryStats) {
        let template = include_str!["../templates/worldmap.html"];

        let html = template.replace(
            "***COUNTRY_PREFIXES_ADOPTION***",
            &stats.adoption_array()
        );

        let html = html.replace(
            "***COUNTRY_PREFIXES_VALID***",
            &stats.valid_array()
        );

        let html = html.replace(
            "***COUNTRY_PREFIXES_QUALITY***",
            &stats.quality_array()
        );

        println!("{}", html);
    }
}


//------------ InvalidsOpts -------------------------------------------------

/// Defines options for the invalids report
pub struct InvalidsOpts {
    dump: PathBuf,
    roas: PathBuf,
    scope: Option<IpResourceSet>
}

impl InvalidsOpts {
    pub fn parse(matches: &ArgMatches) -> Result<Self, Error> {
        let dump_file = matches.value_of("dump").unwrap();
        let dump = PathBuf::from(dump_file);

        let roas_file = matches.value_of("roas").unwrap();
        let roas = PathBuf::from(roas_file);

        let scope = {
            if let Some(scope) = matches.value_of("scope") {
                Some(IpResourceSet::from_str(scope)?)
            } else {
                None
            }
        };

        Ok(InvalidsOpts { dump, roas, scope })
    }
}

/// Used to report invalids, perhaps unsurprisingly.
pub struct InvalidsReport {
    announcements: IpRangeTree<Announcement>,
    roas: IpRangeTree<ValidatedRoaPrefix>
}

impl InvalidsReport {
    pub fn execute(options: &InvalidsOpts) -> Result<(), Error> {

        let announcements: IpRangeTree<Announcement> =
            RisAnnouncements::from_file(&options.dump).unwrap();

        let roas: IpRangeTree<ValidatedRoaPrefix> =
            Roas::from_file(&options.roas).unwrap();

        let report = InvalidsReport { announcements, roas};

        match &options.scope {
            None => report.report_all(),
            Some(set) => report.report_set(set)
        }

        Ok(())
    }

    fn report_announcement(&self, ann: &Announcement) {
        let matching_roas = self.roas.matching_or_less_specific(ann.as_ref());
        let validated = ValidatedAnnouncement::create(ann, &matching_roas);

        if validated.state() == &ValidationState::InvalidAsn ||
            validated.state() == &ValidationState::InvalidLength {
            println!("{:?}", validated)
        }
    }

    fn report_all(&self) {
        for el in self.announcements.inner().iter() {
            for ann in el.value.iter() {
                self.report_announcement(ann)
            }
        }
    }

    fn report_set(&self, set: &IpResourceSet) {
        for range in set.ranges() {
            for ann in self.announcements.matching_or_more_specific(&range) {
                self.report_announcement(ann)
            }
        }
    }
}


//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    WithMessage(String),

    #[display(fmt="{}", _0)]
    IpResourceSet(IpRespourceSetError)
}

impl Error {
    pub fn msg(s: &str) -> Self {
        Error::WithMessage(s.to_string())
    }
}

impl From<IpRespourceSetError> for Error {
    fn from(e: IpRespourceSetError) -> Self { Error::IpResourceSet(e) }
}

