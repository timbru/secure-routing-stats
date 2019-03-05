use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use clap::ArgMatches;
use crate::announcements;
use crate::announcements::Announcements;
use crate::ip::AsnError;
use crate::ip::AsnSet;
use crate::ip::IpResourceSet;
use crate::ip::IpRespourceSetError;
use crate::report::ScopeLimits;
use crate::validation::ValidatedAnnouncement;
use crate::validation::ValidationState;
use crate::validation::VrpImpact;
use crate::vrps;
use crate::vrps::Vrps;
use crate::vrps::ValidatedRoaPayload;


//------------ ResourceReportOpts --------------------------------------------

pub struct ResourceReportOpts {
    ris4: PathBuf,
    ris6: PathBuf,
    vrps: PathBuf,
    scope: ScopeLimits,
    format: ReportFormat
}

impl ResourceReportOpts {
    pub fn scope(&self) -> &ScopeLimits {
        &self.scope
    }

    pub fn parse(matches: &ArgMatches) -> Result<Self, Error> {
        let ris4_file = matches.value_of("ris4").unwrap();
        let ris4 = PathBuf::from(ris4_file);

        let ris6_file = matches.value_of("ris6").unwrap();
        let ris6 = PathBuf::from(ris6_file);

        let vrps_file = matches.value_of("vrps").unwrap();
        let vrps = PathBuf::from(vrps_file);

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
                    f => return Err(Error::WithMessage(
                        format!("Unsupported format: {}. Supported are: json|text", f)))
                }
            } else {
                ReportFormat::Json
            }
        };

        Ok(ResourceReportOpts { ris4, ris6, vrps, scope, format })
    }
}

pub enum ReportFormat {
    Json,
    Text
}


//------------ ResourceReporter ---------------------------------------------

pub struct ResourceReporter<'a> {
    announcements: &'a Announcements,
    vrps: &'a Vrps
}

impl<'a> ResourceReporter<'a> {
    pub fn new(
        announcements: &'a Announcements,
        vrps: &'a Vrps
    ) -> Self {
        ResourceReporter {
            announcements, vrps
        }
    }

    pub fn analyse(&self, scope: &ScopeLimits) -> ResourceReportResult {
        let mut anns_res = AnnouncementsResult::default();
        for ann in self.announcements.in_scope(scope) {
            let matching_roas = self.vrps.containing(ann.as_ref());
            let validated = ValidatedAnnouncement::create(ann, &matching_roas);
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
            vrps: vrps_res
        }
    }

    pub fn execute(options: &ResourceReportOpts) -> Result<(), Error> {

        let announcements = Announcements::from_ris(
            &options.ris4, &options.ris6
        )?;
        let vrps = Vrps::from_file(&options.vrps)?;

        let reporter = ResourceReporter::new(&announcements, &vrps);

        let res = reporter.analyse(options.scope());

        match options.format {
            ReportFormat::Json => println!("{}", serde_json::to_string(&res)?),
            ReportFormat::Text => print!("{}", res)
        }

        Ok(())
    }
}


//------------ ResourceReportResult ------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct ResourceReportResult {
    announcements: AnnouncementsResult,
    vrps: VisibilityResult
}

impl fmt::Display for ResourceReportResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}", self.announcements)?;
        writeln!(f)?;
        writeln!(f, "{}", self.vrps)
    }
}



//------------ AnnouncementsResult -------------------------------------------

#[derive(Clone, Debug, Serialize)]
struct AnnouncementsResult {
    valid: usize,
    invalid_asn: usize,
    invalid_length: usize,
    not_found: usize,
    invalids: Vec<ValidatedAnnouncement>
}

impl Default for AnnouncementsResult {
    fn default() -> Self {
        AnnouncementsResult {
            valid: 0,
            invalid_asn: 0,
            invalid_length: 0,
            not_found: 0,
            invalids: vec![]
        }
    }
}

impl AnnouncementsResult {
    pub fn add(&mut self, ann: ValidatedAnnouncement) {
        match ann.state() {
            ValidationState::Valid => {
                self.valid += 1
            },
            ValidationState::InvalidLength => {
                self.invalid_length += 1;
                self.invalids.push(ann);
            },
            ValidationState::InvalidAsn    => {
                self.invalid_asn += 1;
                self.invalids.push(ann);
            },
            ValidationState::NotFound => {
                self.not_found += 1
            },
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
        if ! self.invalids.is_empty() {
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

#[derive(Clone, Debug, Serialize)]
pub struct VisibilityResult {
    total: usize,
    unseen: Vec<ValidatedRoaPayload>
}

impl Default for VisibilityResult {
    fn default() -> Self {
        VisibilityResult { total: 0, unseen: vec![] }
    }
}

impl VisibilityResult {
    pub fn add(&mut self, vrp: &ValidatedRoaPayload, impact: &VrpImpact) {
        self.total += 1;
        if impact.is_unseen() {
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

    #[display(fmt="{}", _0)]
    IpResourceSet(IpRespourceSetError),

    #[display(fmt="{}", _0)]
    AsnError(AsnError),

    #[display(fmt="{}", _0)]
    AnnouncementsError(announcements::Error),

    #[display(fmt="{}", _0)]
    VrpsError(vrps::Error),

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

impl From<AsnError> for Error {
    fn from(e: AsnError) -> Self { Error::AsnError(e) }
}

impl From<announcements::Error> for Error {
    fn from(e: announcements::Error) -> Self { Error::AnnouncementsError(e) }
}

impl From<vrps::Error> for Error {
    fn from(e: vrps::Error) -> Self { Error::VrpsError(e) }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self { Error::JsonError(e) }
}