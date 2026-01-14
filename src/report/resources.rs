use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use clap::ArgMatches;

use crate::{
    inputs::{
        announcements::{self, Announcements},
        asn::{AsnError, AsnSet},
        ip::{IpResourceSet, IpResourceSetError},
        vrps::{ValidatedRoaPayload, Vrps},
    },
    report::ScopeLimits,
    rpki_stats::{self, RpkiStats},
    validation::{ValidatedAnnouncement, ValidationState, VrpImpact},
};

//------------ ResourceReportOpts --------------------------------------------

pub struct ResourceReportOpts {
    announcements: Vec<PathBuf>,
    rpki_stats: PathBuf,
    scope: ScopeLimits,
    format: ReportFormat,
}

impl ResourceReportOpts {
    pub fn scope(&self) -> &ScopeLimits {
        &self.scope
    }

    pub fn parse(matches: &ArgMatches) -> Result<Self, Error> {
        let mut announcements = vec![];
        for name in matches.values_of("announcements").unwrap() {
            announcements.push(PathBuf::from(name))
        }

        let rpki_stats_file = matches.value_of("rpki").unwrap();
        let rpki_stats = PathBuf::from(rpki_stats_file);

        let ips = {
            if let Some(ips) = matches.value_of("ips") {
                IpResourceSet::from_str(ips)?
            } else {
                IpResourceSet::empty()
            }
        };

        let asns = {
            if let Some(asns) = matches.value_of("asns") {
                AsnSet::from_str(asns)?
            } else {
                AsnSet::empty()
            }
        };

        let scope = ScopeLimits::new(ips, asns);

        let format = {
            if let Some(format) = matches.value_of("format") {
                match format {
                    "json" => ReportFormat::Json,
                    "text" => ReportFormat::Text,
                    "fulljson" => ReportFormat::FullJson,
                    f => {
                        return Err(Error::WithMessage(format!(
                            "Unsupported format: {}. Supported are: json|text|fulljson",
                            f
                        )))
                    }
                }
            } else {
                ReportFormat::Json
            }
        };

        Ok(ResourceReportOpts {
            announcements,
            rpki_stats,
            scope,
            format,
        })
    }
}

pub enum ReportFormat {
    Json,
    Text,
    FullJson,
}

//------------ ResourceReporter ---------------------------------------------

pub struct ResourceReporter<'a> {
    announcements: &'a Announcements,
    vrps: &'a Vrps,
}

impl<'a> ResourceReporter<'a> {
    pub fn new(announcements: &'a Announcements, vrps: &'a Vrps) -> Self {
        ResourceReporter {
            announcements,
            vrps,
        }
    }

    pub fn analyse(&self, scope: &ScopeLimits) -> ResourceReportResult {
        let mut anns_res = AnnouncementsResult::default();
        for ann in self.announcements.in_scope(scope) {
            let matching_roas = self.vrps.containing(ann.as_ref());
            let validated =
                ValidatedAnnouncement::create(ann, &matching_roas);
            anns_res.add(validated);
        }

        let mut vrps_res = VisibilityResult::default();
        for vrp in self.vrps.in_scope(scope) {
            let matching_anns = self.announcements.contained_by(vrp.as_ref());
            let impact = VrpImpact::evaluate(vrp, &matching_anns);
            vrps_res.add(vrp, &impact);
        }

        ResourceReportResult {
            announcements: anns_res,
            vrps: vrps_res,
        }
    }

    pub fn execute(options: &ResourceReportOpts) -> Result<(), Error> {
        let announcements = Announcements::from_ris(&options.announcements)?;
        let rpki_stats =
            RpkiStats::from_routinator_file(&options.rpki_stats)?;

        match options.format {
            ReportFormat::Json => {
                let reporter =
                    ResourceReporter::new(&announcements, rpki_stats.vrps());
                let res = reporter.analyse(options.scope());
                println!("{}", serde_json::to_string(&res)?)
            }
            ReportFormat::Text => {
                let reporter =
                    ResourceReporter::new(&announcements, rpki_stats.vrps());
                let res = reporter.analyse(options.scope());
                print!("{}", res)
            }
            ReportFormat::FullJson => {
                todo!("full report json")
            }
        }

        Ok(())
    }
}

//------------ FullResourceReport --------------------------------------------

#[allow(dead_code)] // This is used for serializing to full json output
pub struct FullResourceReport {
    announcements: Vec<ValidatedAnnouncement>,
    vrps: VisibilityResult,
}

//------------ ResourceReportResult ------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct ResourceReportResult {
    announcements: AnnouncementsResult,
    vrps: VisibilityResult,
}

impl fmt::Display for ResourceReportResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}", self.announcements)?;
        writeln!(f)?;
        writeln!(f, "{}", self.vrps)
    }
}

//------------ AnnouncementsResult -------------------------------------------

#[derive(Clone, Debug, Default, Serialize)]
struct AnnouncementsResult {
    valid: usize,
    invalid_asn: usize,
    invalid_length: usize,
    not_found: usize,
    invalids: Vec<ValidatedAnnouncement>,
}

impl AnnouncementsResult {
    pub fn add(&mut self, ann: ValidatedAnnouncement) {
        match ann.state() {
            ValidationState::Valid => self.valid += 1,
            ValidationState::InvalidLength => {
                self.invalid_length += 1;
                self.invalids.push(ann);
            }
            ValidationState::InvalidAsn => {
                self.invalid_asn += 1;
                self.invalids.push(ann);
            }
            ValidationState::NotFound => self.not_found += 1,
        }
    }

    fn total(&self) -> usize {
        self.valid + self.invalid_asn + self.invalid_length + self.not_found
    }
}

impl fmt::Display for AnnouncementsResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Announcements:")?;
        writeln!(f, "  Totals:")?;
        writeln!(f, "    valid:          {}", self.valid)?;
        writeln!(f, "    invalid length: {}", self.invalid_length)?;
        writeln!(f, "    invalid asn:    {}", self.invalid_asn)?;
        writeln!(f, "    not found:      {}", self.not_found)?;
        writeln!(f, "    total:          {}", self.total())?;
        if !self.invalids.is_empty() {
            writeln!(f)?;
            writeln!(f, "  Invalids:")?;
            for ann in &self.invalids {
                writeln!(f, "    {}", ann)?;
            }
        }
        Ok(())
    }
}

//------------ VisibilityResult ---------------------------------------------

#[derive(Clone, Debug, Default, Serialize)]
pub struct VisibilityResult {
    total: usize,
    unseen: Vec<ValidatedRoaPayload>,
}

impl VisibilityResult {
    pub fn add(&mut self, vrp: &ValidatedRoaPayload, impact: &VrpImpact) {
        self.total += 1;
        if impact == &VrpImpact::Unseen {
            self.unseen.push(vrp.clone())
        }
    }
}

impl fmt::Display for VisibilityResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let unseen = self.unseen.len();

        writeln!(f, "Validated ROA Payloads")?;
        writeln!(f, "  Total:            {}", self.total)?;
        writeln!(f, "  Unseen in BGP:    {}", unseen)?;

        if unseen > 0 {
            for vrp in &self.unseen {
                writeln!(f, "    {}", vrp)?;
            }
        }

        Ok(())
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
    AsnError(AsnError),

    #[display(fmt = "{}", _0)]
    AnnouncementsError(announcements::Error),

    #[display(fmt = "{}", _0)]
    StatsError(rpki_stats::Error),

    #[display(fmt = "{}", _0)]
    JsonError(serde_json::Error),
}

impl Error {
    pub fn msg(s: &str) -> Self {
        Error::WithMessage(s.to_string())
    }
}

impl From<IpResourceSetError> for Error {
    fn from(e: IpResourceSetError) -> Self {
        Error::IpResourceSet(e)
    }
}

impl From<AsnError> for Error {
    fn from(e: AsnError) -> Self {
        Error::AsnError(e)
    }
}

impl From<announcements::Error> for Error {
    fn from(e: announcements::Error) -> Self {
        Error::AnnouncementsError(e)
    }
}

impl From<rpki_stats::Error> for Error {
    fn from(e: rpki_stats::Error) -> Self {
        Error::StatsError(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::JsonError(e)
    }
}
