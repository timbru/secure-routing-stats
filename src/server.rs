//! Run the stats as an HTTP daemon
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::Query;
use axum::extract::State;
use axum::response::Redirect;
use axum::{
    routing::get,
    Router,
    response::Json,
};

use tower_http::services::ServeDir;

use clap::ArgMatches;

use crate::announcements::{self, Announcements};
use crate::report::resources::ResourceReportResult;
use crate::report::world::CountryStats;
use crate::report::ScopeQuery;
use crate::vrps::Vrps;
use crate::delegations::{self, IpDelegations};
use crate::report::{
    resources::ResourceReporter,
    world::WorldStatsReporter,
    ScopeLimits
};
use crate::vrps;

pub struct ServerOpts {
    announcements: Vec<PathBuf>,
    vrps: PathBuf,
    dels: PathBuf,
}

impl ServerOpts {
    pub fn parse(matches: &ArgMatches) -> Result<Self, Error> {
        let mut announcements = vec![];
        for name in matches.values_of("announcements").unwrap().into_iter() {
            announcements.push(PathBuf::from(name))
        }

        let vrps_file = matches.value_of("vrps").unwrap();
        let vrps = PathBuf::from(vrps_file);

        let dels_file = matches.value_of("delegations").unwrap();
        let dels = PathBuf::from(dels_file);

        Ok(ServerOpts {
            announcements,
            vrps,
            dels,
        })
    }
}

#[derive(Debug)]
pub struct Sources {
    announcements: Announcements,
    vrps: Vrps,
    delegations: IpDelegations,
}

#[derive(Debug)]
pub struct StatsServer {
    sources: Sources,
}

impl StatsServer {
    fn create(opts: &ServerOpts) -> Result<Self, Error> {
        let announcements = Announcements::from_ris(&opts.announcements)?;
        let vrps = Vrps::from_file(&opts.vrps)?;
        let delegations = IpDelegations::from_file(&opts.dels)?;

        let sources = Sources {
            announcements,
            vrps,
            delegations,
        };

        Ok(StatsServer { sources })
    }
}

pub struct StatsApp();

impl StatsApp {
    pub async fn run(opts: &ServerOpts) -> Result<(), Error> {
        let state = Arc::new(StatsServer::create(opts)?);

        let app = Router::new()
            .route("/", get( || async { Redirect::temporary("/ui/world.html")} ))
            .nest_service("/ui", ServeDir::new("ui"))
            .route(
                "/rpki-stats-api/details", 
                // get (
                //     {
                //     let state = Arc::clone(&state);
                //         move || Self::details (state)
                //     }
                // )
                get(Self::details).with_state(state.clone())
            )
            .route(
                "/rpki-stats-api/world.csv", 
                get (
                    {
                    let state = Arc::clone(&state);
                        move || Self::world_csv (state)
                    }
                )
            )
            .route(
                "/rpki-stats-api/world.json", 
                get (
                    {
                    let state = Arc::clone(&state);
                        move || Self::world_json (state)
                    }
                )
            );

        // run our app with hyper, listening globally on port 3000
        let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await.unwrap();
        axum::serve(listener, app).await.unwrap();
        
        // let server = server::new(move || Self::new(stats_server.clone()));

        // let address = SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), 8080);

        // server
        //     .bind(address)
        //     .unwrap_or_else(|_| panic!("Cannot bind to: {}", address))
        //     .shutdown_timeout(0)
        //     .run();

        // Ok(())
        Ok(())
    }

    async fn details(
        State(state): State<Arc<StatsServer>>,
        scope_string: Query<ScopeQuery>
    ) -> Json<ResourceReportResult> {

        let limits = 
            ScopeLimits::from_str(&scope_string.scope).unwrap_or(ScopeLimits::empty());

        let reporter = ResourceReporter::new(&state.sources.announcements, &state.sources.vrps);

        Json(reporter.analyse(&limits))
    }

    async fn world_json(state: Arc<StatsServer>) -> Json<CountryStats> {
        let reporter = WorldStatsReporter::new(
            &state.sources.announcements,
            &state.sources.vrps,
            &state.sources.delegations,
        );

        Json(reporter.analyse())
    }

    async fn world_csv(state: Arc<StatsServer>) -> String {
        let reporter = WorldStatsReporter::new(
            &state.sources.announcements,
            &state.sources.vrps,
            &state.sources.delegations,
        );

        let stats = reporter.analyse();
        
        stats.to_csv()
    }


}

//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    AnnouncementsError(announcements::Error),

    #[display(fmt = "{}", _0)]
    VrpsError(vrps::Error),

    #[display(fmt = "{}", _0)]
    DelegationsError(delegations::Error),

    #[display(fmt = "{}", _0)]
    Other(String),
}

impl Error {
    pub fn msg(msg: &str) -> Self {
        Error::Other(msg.to_string())
    }
}

impl From<announcements::Error> for Error {
    fn from(e: announcements::Error) -> Self {
        Error::AnnouncementsError(e)
    }
}

impl From<vrps::Error> for Error {
    fn from(e: vrps::Error) -> Self {
        Error::VrpsError(e)
    }
}

impl From<delegations::Error> for Error {
    fn from(e: delegations::Error) -> Self {
        Error::DelegationsError(e)
    }
}

impl std::error::Error for Error {}
