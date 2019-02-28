extern crate clap;
#[macro_use] extern crate derive_more;
extern crate secure_routing_stats;

use clap::App;
use clap::Arg;
use clap::SubCommand;
use secure_routing_stats::report::{
    self,
    InvalidsOpts,
    InvalidsReport,
    WorldStatsOpts,
    WorldStatsReport
};
use secure_routing_stats::report::UnseenReport;


fn main() {
    match Options::create() {
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        },
        Ok(option) => {
            let res = match option {
                Options::WorldStats(opts) => {
                    WorldStatsReport::execute(&opts)
                }
                Options::Invalids(opts) => {
                    InvalidsReport::execute(&opts)
                }
                Options::Unseen(opts) => {
                    UnseenReport::execute(&opts)
                }
            };
            match res {
                Ok(()) => {},
                Err(e) => {
                    eprintln!("{}", e);
                    ::std::process::exit(1);
                }
            }
        }
    }
}

enum Options {
    WorldStats(WorldStatsOpts),
    Invalids(InvalidsOpts),
    Unseen(InvalidsOpts)
}

impl Options {
    pub fn create() -> Result<Self, Error> {
        let matches = App::new("NLnet Labs RRDP Server")
            .version("0.1b")
            .subcommand(SubCommand::with_name("world")
                .about("Report ROA quality on a per country basis")
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
                    .value_name("json | html | text")
                    .help("Specify output format, defaults to json")
                    .required(false))
            )
            .subcommand(SubCommand::with_name("invalids")
                .about("Report invalid announcements")
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
                .arg(Arg::with_name("format")
                    .short("f")
                    .long("format")
                    .value_name("json | text")
                    .help("Specify output format, defaults to json")
                    .required(false))
            )
            .subcommand(SubCommand::with_name("unseen")
                .about("Report VRPs for which no valid announcement is seen")
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

        if let Some(opts) = matches.subcommand_matches("world") {
            Ok(Options::WorldStats(WorldStatsOpts::parse(opts)?))
        } else if let Some(opts) = matches.subcommand_matches("invalids") {
            Ok(Options::Invalids(InvalidsOpts::parse(opts)?))
        } else if let Some(opts) = matches.subcommand_matches("unseen") {
            Ok(Options::Unseen(InvalidsOpts::parse(opts)?))
        } else {
            Err(Error::msg("No sub-command given. See --help for options."))
        }
    }
}


//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    WithMessage(String),

    #[display(fmt="{}", _0)]
    ReportError(report::Error),
}

impl Error {
    pub fn msg(s: &str) -> Self {
        Error::WithMessage(s.to_string())
    }
}

impl From<report::Error> for Error {
    fn from(e: report::Error) -> Self { Error::ReportError(e) }
}

