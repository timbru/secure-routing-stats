use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::PathBuf,
};

use clap::ArgMatches;
use itertools::Itertools;

use crate::{
    error::Error,
    inputs::{
        asn::Asn,
        ris_path::{AsPath, AsPathsSeen},
        rpki_stats::RpkiStats,
    },
};

//------------ AspaPathResults ----------------------------------------------
#[derive(Debug)]
pub struct AspaPathResults {
    /// Total number of paths observed
    paths: usize,
    paths_no_provider: usize,
    unique_paths_no_provider: usize,

    invalid: usize,
    valid: usize,
    unknown: usize,
    not_covered: usize,
}

impl AspaPathResults {
    pub fn analyse(paths: AsPathsSeen, rpki_stats: RpkiStats) -> Self {
        let aspas = rpki_stats.aspas();

        let total_paths = paths.len();
        eprintln!("Starting to analyse {total_paths} paths");

        let paths_to_no_provider = paths.segments_to_provider_free(aspas);
        let paths_no_provider = paths_to_no_provider.len();

        eprintln!("Processing {paths_no_provider} paths to a provider free network");

        let unique_paths: HashSet<Vec<AsPair>> = paths_to_no_provider
            .into_iter()
            .map(|route| AsPair::get_up_ramp_pairs(route))
            .collect();

        let unique_paths_no_provider = unique_paths.len();

        eprintln!("Found {unique_paths_no_provider} unique paths ");

        let mut invalid = 0;
        let mut valid = 0;
        let mut unknown = 0;
        let mut not_covered = 0;

        let mut done = 0;
        for pairs in unique_paths {
            match AspaToProviderValidation::analyse_as_upramp(pairs, aspas) {
                AspaToProviderValidation::Invalid => invalid += 1,
                AspaToProviderValidation::Valid => valid += 1,
                AspaToProviderValidation::Unknown => unknown += 1,
                AspaToProviderValidation::NotCovered => not_covered += 1,
            }
            done += 1;
            if done % 100000 == 0 {
                eprint!("...{done} ")
            }
        }
        eprintln!("done");
        eprintln!();

        Self {
            paths: total_paths,
            paths_no_provider,
            unique_paths_no_provider,
            invalid,
            valid,
            unknown,
            not_covered,
        }
    }
}

impl fmt::Display for AspaPathResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "all paths:         {}", self.paths)?;
        writeln!(f, "paths no provider: {}", self.paths_no_provider)?;
        writeln!(f, "          -unique: {}", self.unique_paths_no_provider)?;
        writeln!(f, "valid:             {}", self.valid)?;
        writeln!(f, "invalid:           {}", self.invalid)?;
        writeln!(f, "unknown (covered): {}", self.unknown)?;
        writeln!(f, "not covered:       {}", self.not_covered)?;
        Ok(())
    }
}

//------------ AspaPathValidation -------------------------------------------

/// Result of validation of a path segment from customers to provider.
enum AspaToProviderValidation {
    /// None of the AS hops leading up to the leftmost provider
    /// are covered by ASPA
    NotCovered,

    /// At least one AS hop is to not-provider
    Invalid,

    /// All AS hops are covered by ASPA and all are valid
    Valid,

    /// The draft calls other path outcomes unknown, but here
    /// we use unknown exclusively for paths that are at least
    /// partially covered by ASPA
    Unknown,
}

impl AspaToProviderValidation {
    /// Analyses the given path, assuming that it is an upramp, as
    /// one would expect for path segments leading up to and including
    /// the first AS seen from the right that issued an AS0 ASPA.
    pub fn analyse_as_upramp(pairs: Vec<AsPair>, aspas: &HashMap<Asn, HashSet<Asn>>) -> Self {
        let pair_number = pairs.len();
        let mut no_attestation = 0;
        let mut provider = 0;
        let mut not_provider = 0;

        for pair in pairs {
            match pair.aspa_result(aspas) {
                AsPairProviderResult::NoAttestation => no_attestation += 1,
                AsPairProviderResult::Provider => provider += 1,
                AsPairProviderResult::NotProvider => not_provider += 1,
            }
        }

        if no_attestation == pair_number {
            AspaToProviderValidation::NotCovered
        } else if pair_number == provider {
            AspaToProviderValidation::Valid
        } else if not_provider > 0 {
            AspaToProviderValidation::Invalid
        } else {
            AspaToProviderValidation::Unknown
        }
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub struct AsPair {
    from: Asn,
    to: Asn,
}

impl AsPair {
    /// Looks at an AS path with the origin on the right as per convention
    /// in BGP and returns a sorted vec of AS pairs for ASPA verification
    /// sorted from the origin to the left-most provider. Occurences of
    /// repeated ASes in the path (as is used for traffic engineering) are
    /// excluded.
    ///
    /// This vec is empty if the given AS path is empty, or if it contains
    /// only 1 AS.
    pub fn get_up_ramp_pairs(path: AsPath) -> Vec<AsPair> {
        // We do this by
        // - iterating through the path from right to left
        // - get tuples of the right and left asn
        // - and creating pairs from those
        path.into_asns()
            .iter()
            .rev()
            .tuple_windows()
            .filter(|(from, to)| from != to)
            .map(|(from, to)| AsPair {
                from: *from,
                to: *to,
            })
            .collect()
    }
}

impl AsPair {
    pub fn aspa_result(&self, aspas: &HashMap<Asn, HashSet<Asn>>) -> AsPairProviderResult {
        match aspas.get(&self.from) {
            Some(providers) => {
                if providers.contains(&self.to) {
                    AsPairProviderResult::Provider
                } else {
                    AsPairProviderResult::NotProvider
                }
            }
            None => AsPairProviderResult::NoAttestation,
        }
    }
}

pub enum AsPairProviderResult {
    NoAttestation,
    Provider,
    NotProvider,
}

//------------ AspaPathOpts -------------------------------------------------
pub struct AspaPathOpts {
    pub rpki_stats: RpkiStats,
    pub paths: AsPathsSeen,
}

impl AspaPathOpts {
    pub fn parse(matches: &ArgMatches) -> Result<Self, Error> {
        let rpki_stats_file = matches.value_of("rpki").unwrap();
        let paths_file = matches.value_of("paths").unwrap();

        Self::from_files(rpki_stats_file, paths_file)
    }

    pub fn from_files(rpki_stats_file: &str, paths_file: &str) -> Result<Self, Error> {
        let rpki_stats =
            RpkiStats::from_routinator_file(&PathBuf::from(rpki_stats_file)).map_err(Error::msg)?;

        let paths = AsPathsSeen::from_ris_psv_file(&PathBuf::from(paths_file))?;

        Ok(Self { rpki_stats, paths })
    }
}

//------------------------------------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use crate::{
        inputs::ris_path::AsPath,
        report::aspas::{AsPair, AspaPathOpts, AspaPathResults},
    };

    #[test]
    fn analyse_aspa_path() {
        let opts = AspaPathOpts::from_files(
            "test/ris-routes/routinator-short-for-routes.json",
            "test/ris-routes/ris-routes-short.psv",
        )
        .unwrap();

        let results = AspaPathResults::analyse(opts.paths, opts.rpki_stats);

        println!("{:?}", results)
    }

    #[test]
    fn should_get_as_pairs() {
        let as_path = AsPath::new(vec![1.into(), 2.into(), 2.into(), 3.into()]);
        let pairs = AsPair::get_up_ramp_pairs(as_path);
        assert_eq!(
            pairs,
            vec![
                AsPair {
                    from: 3.into(),
                    to: 2.into()
                },
                AsPair {
                    from: 2.into(),
                    to: 1.into()
                },
            ]
        );
    }
}
