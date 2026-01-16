//! Analyse ASPA stats

use core::fmt;
use std::{collections::HashMap, path::PathBuf};

use clap::ArgMatches;

use crate::{
    error::Error,
    inputs::{
        delegations::{AsnDelegations, DelegationState, Region, Registry},
        rpki_stats::RpkiStats,
    },
};

/// Stats for ASPA signing vs registration uptake.
#[derive(Clone, Debug, Default)]
pub struct SignedAspaStats {
    /// Number of registered ASNs
    asns: usize,

    /// Number of customer ASNs with ASPA
    aspas: usize,
}

impl SignedAspaStats {
    pub fn fraction_signed(&self) -> f64 {
        if self.asns > 0 {
            self.aspas as f64 / self.asns as f64
        } else {
            0_f64
        }
    }
}

impl fmt::Display for SignedAspaStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}, {}, {:1}",
            self.asns,
            self.aspas,
            self.fraction_signed() * 100_f64
        )
    }
}

/// Region Stats
pub struct SignedAspaStatsRegional {
    stats: HashMap<Region, SignedAspaStats>,
}

impl SignedAspaStatsRegional {
    pub fn analyse(
        delegations: AsnDelegations,
        rpki_stats: RpkiStats,
    ) -> Self {
        let mut signed_aspa_stats: HashMap<Region, SignedAspaStats> =
            HashMap::new();

        // Count the number of ASNs in all regions first
        for delegation in delegations.all() {
            if delegation.state() == &DelegationState::ASSIGNED {
                let number = delegation.range().len() as usize;

                let world = Region::World;
                let registry = delegation.registry();
                let country = delegation.country();

                signed_aspa_stats.entry(world).or_default().asns += number;
                signed_aspa_stats.entry(registry).or_default().asns += number;
                signed_aspa_stats.entry(country).or_default().asns += number;
            }
        }

        // Go over all signed ASPAs and update the regional stats accordingly
        for customer in rpki_stats.aspas().keys() {
            if let Some(delegation) = delegations.matching(customer) {
                let world = Region::World;
                let registry = delegation.registry();
                let country = delegation.country();

                signed_aspa_stats.entry(world).or_default().aspas += 1;
                signed_aspa_stats.entry(country).or_default().aspas += 1;
                signed_aspa_stats.entry(registry).or_default().aspas += 1;
            } else {
                eprintln!(
                    "warning: cannot find delegation for aspa for ASN: {}",
                    customer
                );
            }
        }

        // for delegation in delegations.
        SignedAspaStatsRegional {
            stats: signed_aspa_stats,
        }
    }
}

impl fmt::Display for SignedAspaStatsRegional {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let empty_stats = SignedAspaStats::default();
        let world = self.stats.get(&Region::World).unwrap_or(&empty_stats);

        writeln!(f, "Region, ASNs, ASPAs, Percentage")?;
        writeln!(f, "world, {world}")?;

        for registry in [
            Registry::Afrinic,
            Registry::Apnic,
            Registry::Arin,
            Registry::Lacnic,
            Registry::RipeNcc,
        ] {
            if let Some(reg_stats) =
                self.stats.get(&Region::Registry(registry))
            {
                writeln!(f, "{registry}, {reg_stats}")?;
            }
        }

        let mut countries: Vec<String> = self
            .stats
            .keys()
            .flat_map(|region| match region {
                Region::Country(country) => Some(country.clone()),
                _ => None,
            })
            .collect();
        countries.sort();

        for country in countries {
            if let Some(reg_stats) =
                self.stats.get(&Region::Country(country.clone()))
            {
                writeln!(f, "{country}, {reg_stats}")?;
            }
        }

        Ok(())
    }
}

//------------ AspaStatOpts -------------------------------------------------

pub struct AspaStatOpts {
    pub delegations: AsnDelegations,
    pub rpki_stats: RpkiStats,
}

impl AspaStatOpts {
    pub fn parse(matches: &ArgMatches) -> Result<Self, Error> {
        let rpki_stats_file = matches.value_of("rpki").unwrap();
        let rpki_stats =
            RpkiStats::from_routinator_file(&PathBuf::from(rpki_stats_file))
                .map_err(Error::msg)?;

        let delegations_file = matches.value_of("delegations").unwrap();
        let delegations =
            AsnDelegations::from_file(&PathBuf::from(delegations_file))
                .map_err(Error::msg)?;

        Ok(AspaStatOpts {
            rpki_stats,
            delegations,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::inputs::rpki_stats::RpkiStats;

    use super::*;

    #[test]
    fn aspa_signing_stats() {
        let delegations = {
            let path = PathBuf::from("test/20250112/delegated-extended.txt");
            AsnDelegations::from_file(&path).unwrap()
        };

        let rpki_stats = {
            let path =
                PathBuf::from("test/20250112/routinator-shortened.json");
            RpkiStats::from_routinator_file(&path).unwrap()
        };

        let stats = SignedAspaStatsRegional::analyse(delegations, rpki_stats);
        let world_stats = stats.stats.get(&Region::World).unwrap();
        assert_eq!(15, world_stats.aspas);
    }
}
