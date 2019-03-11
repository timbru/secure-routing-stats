//! Reporting of the stats found
use std::collections::HashMap;
use std::cmp::Ordering;
use std::fmt;
use std::fmt::Display;
use std::fmt::Write;
use std::path::PathBuf;
use clap::ArgMatches;
use crate::announcements::Announcements;
use crate::delegations::IpDelegations;
use crate::ip::IpRespourceSetError;
use crate::validation::ValidatedAnnouncement;
use crate::validation::ValidationState;
use crate::validation::VrpImpact;
use crate::vrps::Vrps;


//------------ CountryStat --------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CountryStat {
    routes_valid: usize,
    routes_inv_l: usize,
    routes_inv_a: usize,
    routes_not_f: usize,
    vrps_seen: usize,
    vrps_unseen: usize
}

impl CountryStat {
    pub fn add_ann(&mut self, ann: &ValidatedAnnouncement) {
        match ann.state() {
            ValidationState::Valid         => self.routes_valid += 1,
            ValidationState::InvalidLength => self.routes_inv_l += 1,
            ValidationState::InvalidAsn    => self.routes_inv_a += 1,
            ValidationState::NotFound      => self.routes_not_f += 1,
        }
    }

    pub fn add_impact(&mut self, impact: &VrpImpact) {
        if impact.is_unseen() {
            self.vrps_unseen += 1;
        } else {
            self.vrps_seen += 1;
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

    pub fn f_seen(&self) -> Option<f32> {
        let total = self.vrps_seen + self.vrps_unseen;
        if total > 0 {
            Some((self.vrps_seen * 10000 / total) as f32 / 100.)
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
            routes_not_f: 0,
            vrps_seen: 0,
            vrps_unseen: 0
        }
    }
}

impl Display for CountryStat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
"Valid: {}, \
Invalid Length: {}, \
Invalid ASN: {}, \
Not Found: {}, \
VRPS seen: {}, \
VRPS unseen: {}",
            self.routes_valid,
            self.routes_inv_l,
            self.routes_inv_a,
            self.routes_not_f,
            self.vrps_seen,
            self.vrps_unseen
        )
    }
}


//------------ CountryStats -------------------------------------------------

/// This type keeps a map of country code to CountryStat.
#[derive(Clone, Debug, Serialize)]
pub struct CountryStats {
    stats: HashMap<String, CountryStat>
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
        self.stats.entry(cc.to_string()).or_insert_with(CountryStat::default)
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

    pub fn vrps_f_seen_array(&self) -> String {
        let mut s = String::new();

        for cc in self.stats.keys() {
            let cs = &self.stats[&cc.to_string()];
            if cc != "all" {
                if let Some(seen) = cs.f_seen() {
                    writeln!(&mut s, "          ['{}', {}],", cc, seen).unwrap();
                }
            }
        }
        s
    }

    fn get_sorted_countries(&self) -> Vec<CountryStatWithCode> {
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
        writeln!(s, "iso2,coverage,accuracy,seen").unwrap();

        let countries = self.get_sorted_countries();

        for country in countries {
            let coverage = country.stat.f_adoption();
            let accuracy = country.stat.f_quality().unwrap_or(0.);
            let seen = country.stat.f_seen().unwrap_or(0.);

            if coverage > 0. {
                writeln!(
                    s,
                    "{},{},{},{}",
                    country.cc,
                    coverage,
                    accuracy,
                    seen
                ).unwrap();
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
    stat: &'a CountryStat
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
    ris4: PathBuf,
    ris6: PathBuf,
    vrps: PathBuf,
    dels: PathBuf,
    format: WorldStatsFormat
}

impl WorldStatsOpts {
    pub fn parse(matches: &ArgMatches) -> Result<Self, Error> {

        let ris4_file = matches.value_of("ris4").unwrap();
        let ris4 = PathBuf::from(ris4_file);

        let ris6_file = matches.value_of("ris6").unwrap();
        let ris6 = PathBuf::from(ris6_file);

        let vrps_file = matches.value_of("vrps").unwrap();
        let vrps = PathBuf::from(vrps_file);

        let dels_file = matches.value_of("delegations").unwrap();
        let dels = PathBuf::from(dels_file);

        let format = {
            if let Some(format) = matches.value_of("format") {
                match format {
                    "json" => WorldStatsFormat::Json,
                    "text" => WorldStatsFormat::Text,
                    f => return Err(Error::WithMessage(
                        format!("Unsupported format: {}. Supported are: json|html|text", f)))
                }
            } else {
                WorldStatsFormat::Json
            }
        };

        Ok(WorldStatsOpts { ris4, ris6, vrps, dels, format })
    }
}


//------------ WorldStatsFormat ----------------------------------------------

/// Output format. The HTML uses the template in ['templates/world.html'].
pub enum WorldStatsFormat {
    Json,
    Text
}


//------------ WorldStatsReporter --------------------------------------------

/// This type is used to create reports on a per country basis. Can export to
/// json, or HTML using the template included in this source.
pub struct WorldStatsReporter<'a> {
    announcements: &'a Announcements,
    vrps: &'a Vrps,
    delegations: &'a IpDelegations
}

impl<'a> WorldStatsReporter<'a> {

    pub fn new(
        announcements: &'a Announcements,
        vrps: &'a Vrps,
        delegations: &'a IpDelegations
    ) -> Self {
        WorldStatsReporter { announcements, vrps, delegations }
    }

    pub fn analyse(&self) -> CountryStats {
        let mut country_stats = CountryStats::default();

        for ann in self.announcements.all() {
            let matching_roas = self.vrps.containing(ann.as_ref());
            let validated = ValidatedAnnouncement::create(ann, &matching_roas);
            let cc = self.delegations.find_cc(ann.as_ref());

            country_stats.add_ann(&validated, cc);
        }

        for vrp in self.vrps.all() {
            let anns = self.announcements.contained_by(vrp.as_ref());

            let impact = VrpImpact::evaluate(vrp, &anns);
            let cc = self.delegations.find_cc(vrp.as_ref());

            country_stats.add_impact(&impact, cc);
        }

        country_stats
    }

    pub fn execute(options: &WorldStatsOpts) -> Result<(), Error> {
        let announcements = Announcements::from_ris(
            &options.ris4, &options.ris6
        ).unwrap();

        let vrps = Vrps::from_file(&options.vrps).unwrap();

        let delegations = IpDelegations::from_file(&options.dels).unwrap();

        let reporter = WorldStatsReporter::new(&announcements, &vrps, &delegations);

        let stats = reporter.analyse();

        match options.format {
            WorldStatsFormat::Json => Self::json(&stats)?,
            WorldStatsFormat::Text => Self::text(&stats)
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

    #[display(fmt="{}", _0)]
    IpResourceSet(IpRespourceSetError),

    #[display(fmt="{}", _0)]
    JsonError(serde_json::Error),
}

impl Error {
    pub fn msg(s: &str) -> Self {
        Error::WithMessage(s.to_string())
    }
}

impl From<IpRespourceSetError> for Error {
    fn from(e: IpRespourceSetError) -> Self { Error::IpResourceSet(e) }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self { Error::JsonError(e) }
}

