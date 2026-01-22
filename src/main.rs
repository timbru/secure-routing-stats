extern crate clap;
#[macro_use]
extern crate derive_more;
extern crate secure_routing_stats;

use core::fmt;

use clap::{App, Arg, SubCommand};

use secure_routing_stats::{
    report::{
        aspas::{AspaStatOpts, SignedAspaStatsRegional},
        roas::{
            resources::{self, ResourceReportOpts, ResourceReporter},
            world::{self, WorldStatsOpts, WorldStatsReporter},
        },
    },
    server::{self, ServerOpts, StatsApp},
};

#[tokio::main]
async fn main() {
    match Options::create() {
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
        Ok(option) => {
            let res = match option {
                Options::WorldStats(opts) => {
                    WorldStatsReporter::execute(&opts)
                        .map_err(Error::WorldReportError)
                }
                Options::ResourceStats(opts) => {
                    ResourceReporter::execute(&opts)
                        .map_err(Error::ResourceReportError)
                }
                Options::AspaStats(opts) => {
                    let stats = SignedAspaStatsRegional::analyse(
                        &opts.delegations,
                        &opts.rpki_stats,
                    );
                    println!("{stats}");
                    Ok(())
                }
                Options::Daemon(opts) => {
                    StatsApp::run(&opts).await.map_err(Error::DaemonError)
                }
            };
            match res {
                Ok(()) => {}
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
    ResourceStats(ResourceReportOpts),
    AspaStats(AspaStatOpts),
    Daemon(ServerOpts),
}

impl Options {
    pub fn create() -> Result<Self, Error> {
        let matches = App::new("Secure Routing Stats")
            .version("0.3.0")
            .about("Analyse RPKI ROAs and ASPA vs BGP")
            .subcommand(
                SubCommand::with_name("world")
                    .about("Report ROAs and ASPA on a per country basis")
                    .arg(
                        Arg::with_name("announcements")
                            .short("a")
                            .long("announcements")
                            .value_name("FILE")
                            .help("RIS dump file(s)")
                            .required(true)
                            .min_values(1),
                    )
                    .arg(
                        Arg::with_name("rpki")
                            .short("r")
                            .long("rpki")
                            .value_name("FILE")
                            .help("Validated RPKI stats in routinator style JSON.")
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("delegations")
                            .short("d")
                            .long("delegations")
                            .value_name("FILE")
                            .help("Delegation stats (NRO extended delegated stats format).")
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("format")
                            .short("f")
                            .long("format")
                            .value_name("json | text")
                            .help("Specify output format, defaults to json")
                            .required(false),
                    ),
            )
            .subcommand(
                SubCommand::with_name("resources")
                    .about("Report ROA quality on a resource basis")
                    .arg(
                        Arg::with_name("announcements")
                            .short("a")
                            .long("announcements")
                            .value_name("FILE")
                            .help("RIS dump file(s)")
                            .required(true)
                            .min_values(1),
                    )
                    .arg(
                        Arg::with_name("rpki")
                            .short("r")
                            .long("rpki")
                            .value_name("FILE")
                            .help("Validated RPKI stats in routinator style JSON.")
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("ips")
                            .short("i")
                            .long("ips")
                            .value_name("comma separated prefixes/ranges")
                            .help("Optional scope for invalid report. Default: all")
                            .required(false),
                    )
                    .arg(
                        Arg::with_name("asns")
                            .short("x")
                            .long("asns")
                            .value_name("comma separated ASNs / ASN ranges")
                            .help("Optional scope for invalid report. Default: all")
                            .required(false),
                    )
                    .arg(
                        Arg::with_name("format")
                            .short("f")
                            .long("format")
                            .value_name("json | text")
                            .help("Specify output format, defaults to json")
                            .required(false),
                    ),
            )
            .subcommand(
                SubCommand::with_name("aspa")
                    .about("Report ASPA adoption")
                    .arg(
                        Arg::with_name("rpki")
                            .short("r")
                            .long("rpki")
                            .value_name("FILE")
                            .help("Validated RPKI stats in routinator style JSON.")
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("delegations")
                            .short("d")
                            .long("delegations")
                            .value_name("FILE")
                            .help("Delegation stats (NRO extended delegated stats format).")
                            .required(true),
                    )
            )
            .subcommand(
                SubCommand::with_name("daemon")
                    .about("Run as an HTTP server")
                    .arg(
                        Arg::with_name("announcements")
                            .short("a")
                            .long("announcements")
                            .value_name("FILE")
                            .help("RIS dump file(s)")
                            .required(true)
                            .min_values(1),
                    )
                    .arg(
                        Arg::with_name("rpki")
                            .short("r")
                            .long("rpki")
                            .value_name("FILE")
                            .help("Validated RPKI stats in routinator style JSON.")
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("delegations")
                            .short("d")
                            .long("delegations")
                            .value_name("FILE")
                            .help("Delegation stats (NRO extended delegated stats format).")
                            .required(true),
                    ),
            )
            .get_matches();

        if let Some(matches) = matches.subcommand_matches("world") {
            Ok(Options::WorldStats(WorldStatsOpts::parse(matches)?))
        } else if let Some(matches) = matches.subcommand_matches("resources")
        {
            Ok(Options::ResourceStats(ResourceReportOpts::parse(matches)?))
        } else if let Some(matches) = matches.subcommand_matches("aspa") {
            Ok(Options::AspaStats(
                AspaStatOpts::parse(matches).map_err(Error::msg)?,
            ))
        } else if let Some(matches) = matches.subcommand_matches("daemon") {
            Ok(Options::Daemon(ServerOpts::parse(matches)?))
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

    #[display(fmt = "{}", _0)]
    WorldReportError(world::Error),

    #[display(fmt = "{}", _0)]
    ResourceReportError(resources::Error),

    #[display(fmt = "{}", _0)]
    DaemonError(server::Error),
}

impl Error {
    pub fn msg(s: impl fmt::Display) -> Self {
        Error::WithMessage(s.to_string())
    }
}

impl From<world::Error> for Error {
    fn from(e: world::Error) -> Self {
        Error::WorldReportError(e)
    }
}

impl From<resources::Error> for Error {
    fn from(e: resources::Error) -> Self {
        Error::ResourceReportError(e)
    }
}

impl From<server::Error> for Error {
    fn from(e: server::Error) -> Self {
        Error::DaemonError(e)
    }
}
