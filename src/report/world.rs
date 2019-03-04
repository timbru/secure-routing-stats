//! Reporting of the stats found
use std::collections::HashMap;
use std::cmp::Ordering;
use std::fmt;
use std::fmt::Display;
use std::fmt::Write;
use std::path::PathBuf;
use clap::ArgMatches;
use crate::announcements::Announcements;
use crate::delegations::IpDelegation;
use crate::delegations::IpDelegations;
use crate::ip::IpRange;
use crate::ip::IpRangeTree;
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
}

impl Display for CountryStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Overall")?;
        writeln!(f, "  {}", &self.stats["all"])?;
        writeln!(f)?;
        writeln!(f, "Per country:")?;

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

        let mut countries: Vec<CountryStatWithCode> = vec![];

        for (cc, stat) in self.stats.iter() {
            if cc != "all" {
                countries.push(CountryStatWithCode { cc, stat });
            }
        }

        countries.sort();
        for country in countries {
            writeln!(f, "{}: {}", country.cc, country.stat)?;
        }

        Ok(())
    }
}

//------------ WorldStatsOpts -----------------------------------------------

/// Options for the WorldStatsReport
pub struct WorldStatsOpts {
    ris4: PathBuf,
    ris6: PathBuf,
    vrps: PathBuf,
    stats: PathBuf,
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

        let matches = matches.subcommand_matches("world").unwrap();

        let stats_file = matches.value_of("stats").unwrap();
        let stats = PathBuf::from(stats_file);

        let format = {
            if let Some(format) = matches.value_of("format") {
                match format {
                    "json" => WorldStatsFormat::Json,
                    "html" => WorldStatsFormat::Html,
                    "text" => WorldStatsFormat::Text,
                    f => return Err(Error::WithMessage(
                        format!("Unsupported format: {}. Supported are: json|html|text", f)))
                }
            } else {
                WorldStatsFormat::Json
            }
        };

        Ok(WorldStatsOpts { ris4, ris6, vrps, stats, format })
    }
}


//------------ WorldStatsFormat ----------------------------------------------

/// Output format. The HTML uses the template in ['templates/world.html'].
pub enum WorldStatsFormat {
    Json,
    Html,
    Text
}


//------------ WorldStatsReport ----------------------------------------------

/// This type is used to create reports on a per country basis. Can export to
/// json, or HTML using the template included in this source.
pub struct WorldStatsReport;

impl WorldStatsReport {

    pub fn execute(options: &WorldStatsOpts) -> Result<(), Error> {
        let announcements = Announcements::from_ris(
            &options.ris4, &options.ris6
        ).unwrap();

        let vrps = Vrps::from_file(&options.vrps).unwrap();

        let delegations: IpRangeTree<IpDelegation> =
            IpDelegations::from_file(&options.stats).unwrap();


        let mut country_stats = CountryStats::default();

        for ann in announcements.all() {
            let matching_roas = vrps.containing(ann.as_ref());
            let validated = ValidatedAnnouncement::create(ann, &matching_roas);
            let cc = Self::find_cc(&delegations, ann.as_ref());

            country_stats.add_ann(&validated, cc);
        }

        for vrp in vrps.all() {
            let anns = announcements.contained_by(vrp.as_ref());

            let impact = VrpImpact::evaluate(vrp, &anns);
            let cc = Self::find_cc(&delegations, vrp.prefix().as_ref());

            country_stats.add_impact(&impact, cc);
        }

        match options.format {
            WorldStatsFormat::Json => Self::json(&country_stats)?,
            WorldStatsFormat::Html => Self::html(&country_stats)?,
            WorldStatsFormat::Text => Self::text(&country_stats)
        }

        Ok(())
    }

    fn find_cc<'a>(
        delegations: &'a IpRangeTree<IpDelegation>,
        range: &IpRange
    ) -> &'a str {
        let matching_delegations = delegations
            .matching_or_less_specific(range);

        match matching_delegations.first() {
            Some(delegation) => &delegation.cc(),
            None => "XX"
        }
    }

    fn json(stats: &CountryStats) -> Result<(), Error> {
        println!("{}", serde_json::to_string(stats)?);
        Ok(())
    }

    fn html(stats: &CountryStats) -> Result<(), Error> {
        let template = include_str!["../../templates/worldmap.html"];

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

        let html = html.replace(
            "***COUNTRY_VRPS_SEEN***",
            &stats.vrps_f_seen_array()
        );

        println!("{}", html);
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

