//! Analyse ASPA stats

use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Write},
    path::PathBuf,
};

use clap::ArgMatches;

use crate::{
    error::Error,
    inputs::{
        asn::{AS_0, Asn},
        delegations::{AsnDelegations, DelegationState, Region, Registry},
        rpki_stats::RpkiStats,
    },
};

/// Stats for ASPA signing vs registration uptake.
#[derive(Clone, Debug, Default)]
pub struct SignedAspaStats {
    /// Number of registered ASNs
    asns: usize,

    /// Number of ASPAs (should be one per customer AS)
    nr: usize,

    /// Number of AS0 ASPAs
    nr_as0: usize,

    /// Number of AS0 mixed ASPAs
    nr_as0_mix: usize,
}

impl SignedAspaStats {
    pub fn fraction_signed(&self) -> f64 {
        if self.asns > 0 {
            self.nr as f64 / self.asns as f64
        } else {
            0_f64
        }
    }

    pub fn fraction_as0(&self) -> f64 {
        if self.asns > 0 {
            self.nr_as0 as f64 / self.asns as f64
        } else {
            0_f64
        }
    }

    pub fn fraction_as0_mixed(&self) -> f64 {
        if self.asns > 0 {
            self.nr_as0_mix as f64 / self.asns as f64
        } else {
            0_f64
        }
    }

    pub fn add_aspa(&mut self, _customer: &Asn, providers: &HashSet<Asn>) {
        self.nr += 1;
        if providers.contains(&AS_0) {
            if providers.len() == 1 {
                self.nr_as0 += 1;
            } else {
                self.nr_as0_mix += 1;
            }
        }
    }
}

impl fmt::Display for SignedAspaStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}, {}, {:1}, {}, {}",
            self.asns,
            self.nr,
            self.fraction_signed() * 100_f64,
            self.nr_as0,
            self.nr_as0_mix
        )
    }
}

/// Region Stats
pub struct SignedAspaStatsRegional {
    stats: HashMap<Region, SignedAspaStats>,
}

impl SignedAspaStatsRegional {
    pub fn analyse(delegations: &AsnDelegations, rpki_stats: &RpkiStats) -> Self {
        let mut stats: HashMap<Region, SignedAspaStats> = HashMap::new();

        // Count the number of ASNs in all regions first
        for delegation in delegations.all() {
            if delegation.state() == &DelegationState::ASSIGNED {
                let number = delegation.range().len() as usize;

                let world = Region::World;
                let registry = delegation.registry();
                let country = delegation.country();

                stats.entry(world).or_default().asns += number;
                stats.entry(registry).or_default().asns += number;
                stats.entry(country).or_default().asns += number;
            }
        }

        // Go over all signed ASPAs and update the regional stats accordingly
        for (customer, providers) in rpki_stats.aspas().iter() {
            if let Some(delegation) = delegations.matching(customer) {
                let world = Region::World;
                let registry = delegation.registry();
                let country = delegation.country();

                stats
                    .entry(world)
                    .or_default()
                    .add_aspa(customer, providers);
                stats
                    .entry(country)
                    .or_default()
                    .add_aspa(customer, providers);
                stats
                    .entry(registry)
                    .or_default()
                    .add_aspa(customer, providers);
            } else {
                eprintln!(
                    "warning: cannot find delegation for aspa for ASN: {}",
                    customer
                );
            }
        }

        // for delegation in delegations.
        SignedAspaStatsRegional { stats }
    }

    pub fn to_csv(&self) -> String {
        let mut s = String::new();

        writeln!(s, "iso2,coverage").unwrap();

        let countries = self.get_sorted_countries();

        for country in countries {
            if let Some(reg_stats) = self.stats.get(&Region::Country(country.clone())) {
                writeln!(s, "{}, {}", country, reg_stats.fraction_signed() * 100_f64).unwrap();
            }
        }

        s
    }

    fn get_sorted_countries(&self) -> Vec<String> {
        let mut countries: Vec<String> = self
            .stats
            .keys()
            .flat_map(|region| match region {
                Region::Country(country) => Some(country.clone()),
                _ => None,
            })
            .collect();
        countries.sort();
        countries
    }
}

impl fmt::Display for SignedAspaStatsRegional {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let empty_stats = SignedAspaStats::default();
        let world = self.stats.get(&Region::World).unwrap_or(&empty_stats);

        writeln!(f, "Region, ASNs, ASPAs, Percentage, AS0, AS0_mixed")?;
        writeln!(f, "world, {world}")?;

        for registry in [
            Registry::Afrinic,
            Registry::Apnic,
            Registry::Arin,
            Registry::Lacnic,
            Registry::RipeNcc,
        ] {
            if let Some(reg_stats) = self.stats.get(&Region::Registry(registry)) {
                writeln!(f, "{registry}, {reg_stats}")?;
            }
        }

        for country in self.get_sorted_countries() {
            if let Some(reg_stats) = self.stats.get(&Region::Country(country.clone())) {
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
            RpkiStats::from_routinator_file(&PathBuf::from(rpki_stats_file)).map_err(Error::msg)?;

        let delegations_file = matches.value_of("delegations").unwrap();
        let delegations =
            AsnDelegations::from_file(&PathBuf::from(delegations_file)).map_err(Error::msg)?;

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
            let path = PathBuf::from("test/20250112/routinator-shortened.json");
            RpkiStats::from_routinator_file(&path).unwrap()
        };

        let stats = SignedAspaStatsRegional::analyse(&delegations, &rpki_stats);
        let world_stats = stats.stats.get(&Region::World).unwrap();
        assert_eq!(15, world_stats.nr);
    }
}
