extern crate clap;
#[macro_use] extern crate derive_more;
extern crate secure_routing_stats;

use std::path::PathBuf;
use std::str::FromStr;
use secure_routing_stats::announcements::Announcement;
use secure_routing_stats::announcements::RisAnnouncements;
use secure_routing_stats::delegations::IpDelegations;
use secure_routing_stats::roas::Roas;
use secure_routing_stats::ip::IpRangeTree;
use secure_routing_stats::roas::ValidatedRoaPrefix;
use secure_routing_stats::delegations::IpDelegation;
use secure_routing_stats::validation::ValidatedAnnouncement;
use secure_routing_stats::report::CountryStats;
use clap::App;
use clap::Arg;
use clap::SubCommand;
use clap::ArgMatches;
use secure_routing_stats::ip::IpResourceSet;
use secure_routing_stats::ip::IpRespourceSetError;
use secure_routing_stats::validation::ValidationState;


fn main() {
    match Options::create() {
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        },
        Ok(option) => {
            match option {
                Options::WorldStats(worldstats) => { worldstats.execute() }
                Options::Invalids(invalids) => { invalids.execute() }
            }
        }
    }
}

enum Options {
    WorldStats(WorldStatsOpts),
    Invalids(InvalidsOpts)
}

impl Options {
    pub fn create() -> Result<Self, Error> {
        let matches = App::new("NLnet Labs RRDP Server")
            .version("0.1b")
            .subcommand(SubCommand::with_name("world")
                .arg(Arg::with_name("dump")
                    .short("d")
                    .long("dump")
                    .value_name("FILE")
                    .help("Route announcements dump file.")
                    .required(true))
                .arg(Arg::with_name("roas")
                    .short("r")
                    .long("roas")
                    .value_name("FILE")
                    .help("ROAs CSV file.")
                    .required(true))
                .arg(Arg::with_name("stats")
                    .short("s")
                    .long("stats")
                    .value_name("FILE")
                    .help("Delegation stats (NRO extended delegated stats format).")
                    .required(true))
                .arg(Arg::with_name("format")
                    .short("f")
                    .long("format")
                    .value_name("json | html")
                    .help("Specify output format, defaults to json")
                    .required(false))
            )
            .subcommand(SubCommand::with_name("invalids")
                .arg(Arg::with_name("dump")
                    .short("d")
                    .long("dump")
                    .value_name("FILE")
                    .help("Route announcements dump file.")
                    .required(true))
                .arg(Arg::with_name("roas")
                    .short("r")
                    .long("roas")
                    .value_name("FILE")
                    .help("ROAs CSV file.")
                    .required(true))
                .arg(Arg::with_name("scope")
                    .short("s")
                    .long("scope")
                    .value_name("comma separated prefixes/ranges")
                    .help("Optional scope for invalid report. Default: all")
                    .required(false))
            )
            .get_matches();

        if let Some(world) = matches.subcommand_matches("world") {
            Ok(Options::WorldStats(WorldStatsOpts::setup(world)?))
        } else if let Some(invalids) = matches.subcommand_matches("invalids") {
            Ok(Options::Invalids(InvalidsOpts::setup(invalids)?))
        } else {
            Err(Error::msg("No sub-command given. See --help for options."))
        }
    }
}

struct WorldStatsOpts {
    announcements: IpRangeTree<Announcement>,
    roas: IpRangeTree<ValidatedRoaPrefix>,
    delegations: IpRangeTree<IpDelegation>,
    format: WorldOutputFormat
}


enum WorldOutputFormat {
    Json,
    Html
}

impl WorldStatsOpts {
    pub fn setup(matches: &ArgMatches) -> Result<Self, Error> {
        let dump_file = matches.value_of("dump").unwrap();
        let roas_file = matches.value_of("roas").unwrap();
        let stats_file = matches.value_of("stats").unwrap();

        let format = {
            if let Some(format) = matches.value_of("format") {
                match format {
                    "json" => WorldOutputFormat::Json,
                    "html" => WorldOutputFormat::Html,
                    f => return Err(Error::WithMessage(
                        format!("Unsupported format: {}", f)))
                }
            } else {
                WorldOutputFormat::Json
            }
        };


        let announcements: IpRangeTree<Announcement> =
            RisAnnouncements::from_file(&PathBuf::from(dump_file)).unwrap();

        let roas: IpRangeTree<ValidatedRoaPrefix> =
            Roas::from_file(&PathBuf::from(roas_file)).unwrap();

        let delegations: IpRangeTree<IpDelegation> =
            IpDelegations::from_file(&PathBuf::from(stats_file)).unwrap();

        Ok(WorldStatsOpts { announcements, roas, delegations, format })
    }

    pub fn execute(&self) {
        let mut country_stats = CountryStats::default();

        for el in self.announcements.inner().iter() {
            for ann in el.value.iter() {

                let matching_roas = self.roas.matching_or_less_specific(ann.as_ref());
                let validated = ValidatedAnnouncement::create(ann, &matching_roas);

                let matching_delegations = self.delegations.matching_or_less_specific(ann.as_ref());

                let cc = match matching_delegations.first() {
                    Some(delegation) => &delegation.cc(),
                    None => "XX"
                };

                country_stats.add(&validated, cc);
            }
        }

        match self.format {
            WorldOutputFormat::Json => Self::json(&country_stats),
            WorldOutputFormat::Html => Self::html(&country_stats)
        }

    }

    fn json(stats: &CountryStats) {
        println!("{:?}", stats);
    }

    fn html(stats: &CountryStats) {
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

        println!("{}", html);
    }

}



struct InvalidsOpts {
    announcements: IpRangeTree<Announcement>,
    roas: IpRangeTree<ValidatedRoaPrefix>,
    scope: Option<IpResourceSet>
}

impl InvalidsOpts {
    pub fn setup(matches: &ArgMatches) -> Result<Self, Error> {
        let dump_file = matches.value_of("dump").unwrap();
        let roas_file = matches.value_of("roas").unwrap();

        let scope = {
            if let Some(scope) = matches.value_of("scope") {
                Some(IpResourceSet::from_str(scope)?)
            } else {
                None
            }
        };

        let announcements: IpRangeTree<Announcement> =
            RisAnnouncements::from_file(&PathBuf::from(dump_file)).unwrap();

        let roas: IpRangeTree<ValidatedRoaPrefix> =
            Roas::from_file(&PathBuf::from(roas_file)).unwrap();

        Ok(InvalidsOpts{ announcements, roas, scope })
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

    pub fn execute(&self) {
        match &self.scope {
            None => self.report_all(),
            Some(set) => self.report_set(set)
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

