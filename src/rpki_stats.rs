//! Validated RPKI Stats

use std::{fmt::Display, fs::File, path::Path};

use chrono::{DateTime, Utc};

use crate::{
    routinator_json::RoutinatorStatsJson,
    vrps::{ValidatedRoaPayload, Vrps},
};

//------------ RpkiStats ----------------------------------------------------

/// Validated RPKI Stats
///
/// For now, this is built using routinator style JSON as input,
/// but this can support CCR in future.
#[derive(Debug)]
pub struct RpkiStats {
    #[allow(dead_code)]
    generated: DateTime<Utc>,
    vrps: Vrps,
}

impl RpkiStats {
    pub fn from_routinator_file(path: &Path) -> Result<Self, Error> {
        let file = File::open(path).map_err(|_| Error::read_error(path))?;

        serde_json::from_reader::<File, RoutinatorStatsJson>(file)
            .map(|routinator| routinator.into())
            .map_err(Error::parse_error)
    }

    pub fn vrps(&self) -> &Vrps {
        &self.vrps
    }
}

impl From<RoutinatorStatsJson> for RpkiStats {
    fn from(routinator: RoutinatorStatsJson) -> Self {
        let generated =
            DateTime::from_timestamp(routinator.metadata.generated, 0)
                .unwrap();

        let payloads: Vec<ValidatedRoaPayload> = routinator
            .roas
            .into_iter()
            .map(|roa| {
                ValidatedRoaPayload::new(roa.asn, roa.prefix, roa.max_length)
            })
            .collect();

        let vrps = Vrps::from_payloads(payloads);

        RpkiStats { generated, vrps }
    }
}

//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Cannot read file: {}", _0)]
    CannotRead(String),

    #[display(fmt = "Error parsing JSON: {}", _0)]
    ParseError(String),
}

impl Error {
    fn read_error(path: &Path) -> Self {
        Error::CannotRead(path.to_string_lossy().to_string())
    }
    fn parse_error(e: impl Display) -> Self {
        Error::ParseError(format!("{}", e))
    }
}
