//! Run the stats as an HTTP daemon

use crate::announcements::Announcements;
use crate::vrps::Vrps;
use actix_web::http::Method;
use actix_web::http::StatusCode;
use actix_web::pred;
use actix_web::server;
use actix_web::App;
use actix_web::HttpResponse;
use announcements;
use clap::ArgMatches;
use delegations;
use delegations::IpDelegations;
use report::resources::ResourceReporter;
use report::world::WorldStatsReporter;
use report::ScopeLimits;
use serde::Serialize;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use vrps;

const NOT_FOUND: &[u8] = include_bytes!("../ui/not_found.html");

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

pub struct StatsApp(App<Arc<StatsServer>>);

impl StatsApp {
    pub fn new(server: Arc<StatsServer>) -> Self {
        let app = App::with_state(server)
            .resource("/", |r| {
                r.method(Method::GET).f(|_r| {
                    HttpResponse::Found()
                        .header("location", "/ui/world.html")
                        .finish()
                })
            })
            .resource("/rpki-stats-api/details", |r| {
                r.method(Method::GET).f(Self::details);
            })
            .resource("/rpki-stats-api/world.json", |r| {
                r.method(Method::GET).f(Self::world_json);
            })
            .resource("/rpki-stats-api/world.csv", |r| {
                r.method(Method::GET).f(Self::world_csv);
            })
            .default_resource(|r| {
                // 404 for GET request
                r.method(Method::GET).f(Self::p404);

                // all requests that are not `GET`
                r.route()
                    .filter(pred::Not(pred::Get()))
                    .f(|_req| HttpResponse::MethodNotAllowed());
            });

        let app = with_statics(app);

        StatsApp(app)
    }

    pub fn run(opts: &ServerOpts) -> Result<(), Error> {
        let stats_server = Arc::new(StatsServer::create(opts)?);

        let server = server::new(move || Self::new(stats_server.clone()));

        let address = SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), 8080);

        server
            .bind(address)
            .unwrap_or_else(|_| panic!("Cannot bind to: {}", address))
            .shutdown_timeout(0)
            .run();

        Ok(())
    }

    fn p404(_req: &HttpRequest) -> HttpResponse {
        HttpResponse::build(StatusCode::NOT_FOUND).body(NOT_FOUND)
    }

    fn details(req: &HttpRequest) -> HttpResponse {
        let server: &Arc<StatsServer> = req.state();

        let limits = match req.query().get("scope") {
            None => ScopeLimits::empty(),
            Some(scope_str) => match ScopeLimits::from_str(scope_str) {
                Ok(scope) => scope,
                Err(_) => return Self::user_error("Can't parse scope"),
            },
        };

        let reporter = ResourceReporter::new(&server.sources.announcements, &server.sources.vrps);

        let stats = reporter.analyse(&limits);

        Self::render_json(&stats)
    }

    fn world_json(req: &HttpRequest) -> HttpResponse {
        let server: &Arc<StatsServer> = req.state();
        let reporter = WorldStatsReporter::new(
            &server.sources.announcements,
            &server.sources.vrps,
            &server.sources.delegations,
        );

        let stats = reporter.analyse();

        Self::render_json(&stats)
    }

    fn world_csv(req: &HttpRequest) -> HttpResponse {
        let server: &Arc<StatsServer> = req.state();
        let reporter = WorldStatsReporter::new(
            &server.sources.announcements,
            &server.sources.vrps,
            &server.sources.delegations,
        );

        let stats = reporter.analyse();
        let csv = stats.to_csv();

        HttpResponse::Ok().content_type("text/csv").body(csv)
    }

    fn render_json<O: Serialize>(obj: &O) -> HttpResponse {
        match serde_json::to_string(obj) {
            Ok(json) => HttpResponse::Ok()
                .content_type("application/json")
                .body(json),
            Err(_) => Self::server_error(),
        }
    }

    fn server_error() -> HttpResponse {
        HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .body("I'm sorry Dave, I'm afraid I can't do that.")
    }

    fn user_error(msg: &str) -> HttpResponse {
        HttpResponse::build(StatusCode::BAD_REQUEST).body(msg.to_string())
    }
}

//------------ IntoHttpHandler -----------------------------------------------

impl server::IntoHttpHandler for StatsApp {
    type Handler = <App<Arc<StatsServer>> as server::IntoHttpHandler>::Handler;

    fn into_handler(self) -> Self::Handler {
        self.0.into_handler()
    }
}

//------------ HttpRequest ---------------------------------------------------

pub type HttpRequest = actix_web::HttpRequest<Arc<StatsServer>>;

//------------ Definition of Statics for UI content --------------------------

static HTML: &[u8] = b"text/html";
static CSS: &[u8] = b"text/css";
static JS: &[u8] = b"application/javascript";
static JSON: &[u8] = b"application/json";

fn with_statics<S: 'static>(app: App<S>) -> App<S> {
    statics!(app,
        "world.html" => HTML,
        "css/bootstrap.min.css" => CSS,
        "css/d3.geomap.css" => CSS,
        "js/axios.min.js" => JS,
        "js/bootstrap.min.js" => JS,
        "js/d3.geomap.dependencies.min.js" => JS,
        "js/d3.geomap.min.js" => JS,
        "js/jquery-3.3.1.min.js" => JS,
        "js/vue.min.js" => JS,
        "json/countries_with_iso2.json" => JSON,
    )
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

impl actix_web::ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).body(format!("{}", self))
    }
}
