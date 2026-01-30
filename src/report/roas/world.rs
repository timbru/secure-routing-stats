//! Reporting of the stats found
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use std::fmt::Write;
use std::path::PathBuf;

use clap::ArgMatches;

use crate::{
    inputs::{
        announcements::Announcements, delegations::IpDelegations,
        ip::IpResourceSetError, rpki_stats::RpkiStats,
    },
    report::roas::validation::{
        ValidatedAnnouncement, ValidationState, VrpImpact,
    },
};

//------------ CountryStat --------------------------------------------------

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CountryStat {
    routes_valid: usize,
    routes_inv_l: usize,
    routes_inv_a: usize,
    routes_not_f: usize,
    vrps_seen: usize,
    vrps_unseen: usize,
    vrps_too_permisive: usize,
}

impl CountryStat {
    pub fn add_ann(&mut self, ann: &ValidatedAnnouncement) {
        match ann.state() {
            ValidationState::Valid => self.routes_valid += 1,
            ValidationState::InvalidLength => self.routes_inv_l += 1,
            ValidationState::InvalidAsn => self.routes_inv_a += 1,
            ValidationState::NotFound => self.routes_not_f += 1,
        }
    }

    pub fn add_impact(&mut self, impact: &VrpImpact) {
        match impact {
            VrpImpact::Seen => self.vrps_seen += 1,
            VrpImpact::Unseen => self.vrps_unseen += 1,
            VrpImpact::TooPermissive => self.vrps_too_permisive += 1,
        }
    }

    fn total(&self) -> usize {
        self.routes_valid
            + self.routes_inv_l
            + self.routes_inv_a
            + self.routes_not_f
    }

    fn covered(&self) -> usize {
        self.routes_valid + self.routes_inv_a + self.routes_inv_l
    }

    pub fn f_adoption(&self) -> f32 {
        if self.total() == 0 {
            0_f32
        } else {
            (self.covered() * 10000 / self.total()) as f32 / 100.
        }
    }

    pub fn has_adoption(&self) -> bool {
        self.routes_valid + self.routes_inv_a + self.routes_inv_l > 0
    }

    pub fn f_valid(&self) -> f32 {
        if self.total() == 0 {
            0_f32
        } else {
            (self.routes_valid * 10000 / self.total()) as f32 / 100.
        }
    }

    pub fn f_quality(&self) -> Option<f32> {
        if self.covered() > 0 {
            Some((self.routes_valid * 10000 / self.covered()) as f32 / 100.)
        } else {
            None
        }
    }

    fn total_vrps(&self) -> usize {
        self.vrps_seen + self.vrps_unseen + self.vrps_too_permisive
    }

    pub fn f_seen(&self) -> Option<f32> {
        let total = self.total_vrps();
        if total > 0 {
            Some((self.vrps_seen * 10000 / total) as f32 / 100.)
        } else {
            None
        }
    }

    pub fn f_unseen(&self) -> Option<f32> {
        let total = self.total_vrps();
        if total > 0 {
            Some((self.vrps_unseen * 10000 / total) as f32 / 100.)
        } else {
            None
        }
    }

    pub fn f_too_permissive(&self) -> Option<f32> {
        let total = self.total_vrps();
        if total > 0 {
            Some((self.vrps_too_permisive * 10000 / total) as f32 / 100.)
        } else {
            None
        }
    }
}

impl Display for CountryStat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Valid: {}, \
Invalid Length: {}, \
Invalid ASN: {}, \
Not Found: {}, \
VRPS seen: {}, \
VRPS unseen: {}, \
VRPS too permissive: {}",
            self.routes_valid,
            self.routes_inv_l,
            self.routes_inv_a,
            self.routes_not_f,
            self.vrps_seen,
            self.vrps_unseen,
            self.vrps_too_permisive,
        )
    }
}

//------------ CountryStats -------------------------------------------------

/// This type keeps a map of country code to CountryStat.
#[derive(Clone, Debug, Serialize)]
pub struct CountryStats {
    stats: HashMap<String, CountryStat>,
}

impl Default for CountryStats {
    fn default() -> Self {
        let mut stats = HashMap::new();
        stats.insert("all".to_string(), CountryStat::default());
        CountryStats { stats }
    }
}

impl CountryStats {
    fn get_cc(&mut self, cc: &str) -> &mut CountryStat {
        self.stats.entry(cc.to_string()).or_default()
    }

    /// Adds a ValidatedAnnouncement to the stats for the given country code.
    /// Also adds this to the overall 'all' countries category.
    pub fn add_ann(&mut self, ann: &ValidatedAnnouncement, cc: &str) {
        self.get_cc(cc).add_ann(ann);
        self.get_cc("all").add_ann(ann);
    }

    /// Adds a ValidatedAnnouncement to the stats for the given country code.
    /// Also adds this to the overall 'all' countries category.
    pub fn add_impact(&mut self, imp: &VrpImpact, cc: &str) {
        self.get_cc(cc).add_impact(imp);
        self.get_cc("all").add_impact(imp);
    }

    /// Returns an adoption array string of country codes to percentages of
    /// adoption for inclusion in the HTML output.
    pub fn adoption_array(&self) -> String {
        let mut s = String::new();

        for cc in self.stats.keys() {
            let cs = &self.stats[&cc.to_string()];
            if cc != "all" {
                writeln!(
                    &mut s,
                    "          ['{}', {}],",
                    cc,
                    cs.f_adoption()
                )
                .unwrap();
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
                writeln!(&mut s, "          ['{}', {}],", cc, cs.f_valid())
                    .unwrap();
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
            if cc != "all"
                && let Some(quality) = cs.f_quality()
            {
                writeln!(&mut s, "          ['{}', {}],", cc, quality)
                    .unwrap();
            }
        }
        s
    }

    pub fn vrps_f_seen_array(&self) -> String {
        let mut s = String::new();

        for cc in self.stats.keys() {
            let cs = &self.stats[&cc.to_string()];
            if cc != "all"
                && let Some(seen) = cs.f_seen()
            {
                writeln!(&mut s, "          ['{}', {}],", cc, seen).unwrap();
            }
        }
        s
    }

    fn get_sorted_countries(&self) -> Vec<CountryStatWithCode<'_>> {
        let mut countries: Vec<CountryStatWithCode> = vec![];

        for (cc, stat) in self.stats.iter() {
            if cc != "all" {
                countries.push(CountryStatWithCode { cc, stat });
            }
        }

        countries.sort();
        countries
    }

    pub fn to_csv(&self) -> String {
        let mut s = String::new();
        writeln!(s, "iso2,coverage,accuracy,seen,too_permissive,unseen")
            .unwrap();

        let countries = self.get_sorted_countries();

        for country in countries {
            let coverage = country.stat.f_adoption();
            let accuracy = country.stat.f_quality().unwrap_or(0.);
            let seen = country.stat.f_seen().unwrap_or(0.);
            let too_permissive =
                country.stat.f_too_permissive().unwrap_or(0.);
            let unseen = country.stat.f_unseen().unwrap_or(0.);

            if country.stat.has_adoption() {
                writeln!(
                    s,
                    "{},{},{},{},{},{}",
                    country.cc,
                    coverage,
                    accuracy,
                    seen,
                    too_permissive,
                    unseen
                )
                .unwrap();
            }
        }

        s
    }
}

impl Display for CountryStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Overall")?;
        writeln!(f, "  {}", &self.stats["all"])?;
        writeln!(f)?;
        writeln!(f, "Per country:")?;

        let countries = self.get_sorted_countries();
        for country in countries {
            writeln!(f, "{}: {}", country.cc, country.stat)?;
        }

        Ok(())
    }
}

#[derive(Eq, PartialEq)]
struct CountryStatWithCode<'a> {
    cc: &'a str,
    stat: &'a CountryStat,
}

impl<'a> Ord for CountryStatWithCode<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cc.cmp(other.cc)
    }
}

impl<'a> PartialOrd for CountryStatWithCode<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

//------------ WorldStatsOpts -----------------------------------------------

/// Options for the WorldStatsReport
pub struct WorldStatsOpts {
    announcements: Vec<PathBuf>,
    rpki_stats: PathBuf,
    delegations: PathBuf,
    format: WorldStatsFormat,
}

impl WorldStatsOpts {
    pub fn parse(matches: &ArgMatches) -> Result<Self, Error> {
        let mut announcements = vec![];
        for name in matches.values_of("announcements").unwrap() {
            announcements.push(PathBuf::from(name))
        }

        let rpki_stats_file = matches.value_of("rpki").unwrap();
        let rpki_stats = PathBuf::from(rpki_stats_file);

        let delegations_file = matches.value_of("delegations").unwrap();
        let delegations = PathBuf::from(delegations_file);

        let format = {
            if let Some(format) = matches.value_of("format") {
                match format {
                    "json" => WorldStatsFormat::Json,
                    "text" => WorldStatsFormat::Text,
                    f => {
                        return Err(Error::WithMessage(format!(
                            "Unsupported format: {}. Supported are: json|html|text",
                            f
                        )));
                    }
                }
            } else {
                WorldStatsFormat::Json
            }
        };

        Ok(WorldStatsOpts {
            announcements,
            rpki_stats,
            delegations,
            format,
        })
    }
}

//------------ WorldStatsFormat ----------------------------------------------

/// Output format. The HTML uses the template in ['templates/world.html'].
pub enum WorldStatsFormat {
    Json,
    Text,
}

//------------ WorldStatsReporter --------------------------------------------

/// This type is used to create reports on a per country basis. Can export to
/// json, or HTML using the template included in this source.
pub struct WorldStatsReporter<'a> {
    announcements: &'a Announcements,
    rpki_stats: &'a RpkiStats,
    delegations: &'a IpDelegations,
}

impl<'a> WorldStatsReporter<'a> {
    pub fn new(
        announcements: &'a Announcements,
        rpki_stats: &'a RpkiStats,
        delegations: &'a IpDelegations,
    ) -> Self {
        WorldStatsReporter {
            announcements,
            rpki_stats,
            delegations,
        }
    }

    pub fn analyse(&self) -> CountryStats {
        let mut country_stats = CountryStats::default();

        let now = std::time::SystemTime::now();

        let nr_anns = self.announcements.all().len();
        let nr_vrps = self.rpki_stats.vrps().all().len();

        eprint!("Start.....");

        for ann in self.announcements.all() {
            let matching_roas =
                self.rpki_stats.vrps().containing(ann.as_ref());
            let validated =
                ValidatedAnnouncement::create(ann, &matching_roas);
            let cc = self.delegations.find_cc(ann.as_ref());

            country_stats.add_ann(&validated, cc);
        }

        for vrp in self.rpki_stats.vrps().all() {
            let anns = self.announcements.contained_by(vrp.as_ref());

            let impact = VrpImpact::evaluate(vrp, &anns);
            let cc = self.delegations.find_cc(vrp.as_ref());

            country_stats.add_impact(&impact, cc);
        }

        eprintln!(
            "done ({} ms {} anns {} vrps)",
            now.elapsed().unwrap().as_millis(),
            nr_anns,
            nr_vrps
        );

        country_stats
    }

    pub fn execute(options: &WorldStatsOpts) -> Result<(), Error> {
        let announcements = Announcements::from_ris(&options.announcements)
            .map_err(Error::msg)?;

        let rpki_stats = RpkiStats::from_routinator_file(&options.rpki_stats)
            .map_err(Error::msg)?;

        let delegations = IpDelegations::from_file(&options.delegations)
            .map_err(Error::msg)?;

        let reporter = WorldStatsReporter::new(
            &announcements,
            &rpki_stats,
            &delegations,
        );

        let stats = reporter.analyse();

        match options.format {
            WorldStatsFormat::Json => Self::json(&stats)?,
            WorldStatsFormat::Text => Self::text(&stats),
        }

        Ok(())
    }

    fn json(stats: &CountryStats) -> Result<(), Error> {
        println!("{}", serde_json::to_string(stats)?);
        Ok(())
    }

    fn text(stats: &CountryStats) {
        println!("{}", stats);
    }
}

//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    WithMessage(String),

    #[display(fmt = "{}", _0)]
    IpResourceSet(IpResourceSetError),

    #[display(fmt = "{}", _0)]
    JsonError(serde_json::Error),
}

impl Error {
    pub fn msg(s: impl std::fmt::Display) -> Self {
        Error::WithMessage(s.to_string())
    }
}

impl From<IpResourceSetError> for Error {
    fn from(e: IpResourceSetError) -> Self {
        Error::IpResourceSet(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::JsonError(e)
    }
}
