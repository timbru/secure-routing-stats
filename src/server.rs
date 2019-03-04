//! Run the stats as an HTTP daemon

use crate::announcements::Announcements;
use crate::vrps::Vrps;
use actix_web::App;
use std::path::PathBuf;
use announcements;
use vrps;
use actix_web::http::Method;
use actix_web::http::StatusCode;
use actix_web::pred;
use actix_web::HttpResponse;
use clap::ArgMatches;
use std::sync::Arc;
use actix_web::server;
use std::net::SocketAddr;
use std::net::IpAddr;
use std::str::FromStr;

const NOT_FOUND: &[u8] = include_bytes!("../templates/not_found.html");


pub struct ServerOpts {
    ris4: PathBuf,
    ris6: PathBuf,
    vrps: PathBuf,
}

impl ServerOpts {
    pub fn parse(matches: &ArgMatches) -> Result<Self, Error> {
        let ris4_file = matches.value_of("ris4").unwrap();
        let ris4 = PathBuf::from(ris4_file);

        let ris6_file = matches.value_of("ris6").unwrap();
        let ris6 = PathBuf::from(ris6_file);

        let vrps_file = matches.value_of("vrps").unwrap();
        let vrps = PathBuf::from(vrps_file);

        Ok(ServerOpts { ris4, ris6, vrps })
    }
}

#[derive(Debug)]
pub struct Sources {
    announcements: Announcements,
    vrps: Vrps
}

#[derive(Debug)]
pub struct StatsServer {
    sources: Sources
}

impl StatsServer {
    fn create(opts: &ServerOpts) -> Result<Self, Error> {
        let announcements = Announcements::from_ris(&opts.ris4, &opts.ris6)?;
        let vrps = Vrps::from_file(&opts.vrps)?;

        let sources = Sources { announcements, vrps };

        Ok(StatsServer { sources })
    }
}

pub struct StatsApp(App<Arc<StatsServer>>);

impl StatsApp {
    pub fn new(server: Arc<StatsServer>) -> Self {
        let app = App::with_state(server)
            .default_resource(|r| {
                // 404 for GET request
                r.method(Method::GET).f(Self::p404);

                // all requests that are not `GET`
                r.route().filter(pred::Not(pred::Get())).f(
                    |_req| HttpResponse::MethodNotAllowed());
            });

        StatsApp(app)
    }

    pub fn run(opts: &ServerOpts) -> Result<(), Error> {

        let stats_server = Arc::new(StatsServer::create(&opts)?);

        let server = server::new(move || Self::new(stats_server.clone()));

        let address = SocketAddr::new(
            IpAddr::from_str("127.0.0.1").unwrap(),
            8080
        );

        server.bind(address)
            .unwrap_or_else(|_| panic!("Cannot bind to: {}", address))
            .shutdown_timeout(0)
            .run();

        Ok(())
    }

    fn p404(_req: &HttpRequest) -> HttpResponse {
        HttpResponse::build(StatusCode::NOT_FOUND).body(NOT_FOUND)
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



//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt="{}", _0)]
    AnnouncementsError(announcements::Error),

    #[display(fmt="{}", _0)]
    VrpsError(vrps::Error),
}

impl From<announcements::Error> for Error {
    fn from(e: announcements::Error) -> Self { Error::AnnouncementsError(e) }
}

impl From<vrps::Error> for Error {
    fn from(e: vrps::Error) -> Self { Error::VrpsError(e) }
}