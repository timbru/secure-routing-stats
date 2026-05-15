//! Process path information from RIS

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    str::FromStr,
};

use crate::{
    error::Error,
    inputs::{
        asn::{AS_0, Asn},
        ip::IpPrefix,
    },
};

/// An ordered AS Path with the origin on the right
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AsPath(Vec<Asn>);

impl AsPath {
    pub fn new(asns: Vec<Asn>) -> Self {
        Self(asns)
    }

    pub fn asns(&self) -> &Vec<Asn> {
        &self.0
    }
}

impl AsPath {
    /// Returns the right-hand segment of this path leading up to and
    /// including a provider free network, with an AS0 ASPA object, if
    /// such a segment exists.
    ///
    /// Otherwise returns None.
    pub fn segment_to_provider_free(&self, aspas: &HashMap<Asn, HashSet<Asn>>) -> Option<Self> {
        let mut segment_asns = vec![];

        // Go through the elements from the right, so in reverse order
        for asn in self.0.iter().rev() {
            // 'push' the elements into the front rather than the back
            // so that the resulting segment retains the normal BGP
            // order. This has a cost of O(n) but these segments are
            // small enough that we don't need to care.
            segment_asns.insert(0, *asn);

            if let Some(providers) = aspas.get(asn) {
                if providers.contains(&AS_0) {
                    return Some(AsPath(segment_asns));
                }
            }
        }

        None
    }
}

/// Tracks AsPaths that were seen and counts them
#[derive(Debug)]
pub struct AsPathsSeen(HashMap<AsPath, usize>);

impl AsPathsSeen {
    /// Parse AS Paths from a pipe separated file containing paths
    /// seen by RIS.
    ///
    /// Get the full parquet file of the day which can be found here:
    ///
    /// https://data.ris.ripe.net/derived/prototypes/parquet/v0/bview/
    ///
    /// Download it and then open it with duckdb and do the following:
    ///
    /// SET preserve_insertion_order = false;
    ///
    /// This is needed because otherwise your system will run out of
    /// memory as duckdb tries to optimise output. We don't don't care about
    /// the order for our input file that we will make. We will deal with it here.
    ///
    /// Then:
    /// copy (select as_path, prefix from 'TABLE-O-DAY') to './ris-routes.psv' (FORMAT CSV, DELIMITER '|', HEADER FALSE);
    ///
    /// It should like a bit like:
    /// [513, 25091, 25091]|0.0.0.0/0
    /// [34019, 29169]|0.0.0.0/0
    /// [29222, 3356]|0.0.0.0/0
    /// [6730, 65300, 6830]|0.0.0.0/0
    /// [42473, 9002]|0.0.0.0/0
    /// [559, 13335]|1.0.0.0/24
    ///
    /// When reading we will skip IPv4 prefixes </8 or >/24 and IPv6 </12 or >/48
    ///
    pub fn from_ris_psv_file(path: &Path) -> Result<Self, Error> {
        let mut as_paths_map = HashMap::new();

        let file = File::open(path).map_err(Error::msg)?;
        let reader = BufReader::new(file);

        for line_result in reader.lines() {
            let line = line_result.map_err(Error::msg)?;

            // Line should have format like:
            // [ as1, as2, as3 ]|pfx
            let bits: Vec<&str> = line.split('|').collect();
            if bits.len() != 2 {
                return Err(Error::msg(format!(
                    "Cannot read this line in RIS file: {line}"
                )));
            }

            // If we can't parse the as path, then this is likely becuase it
            // contains an AS_SET and we just want to skip it here.
            if let Ok(asn_numbers) = serde_json::from_str::<Vec<u32>>(bits[0]) {
                let as_path_vec: Vec<Asn> = asn_numbers.into_iter().map(Asn::from).collect();
                let as_path = AsPath(as_path_vec);

                if let Ok(pfx) = IpPrefix::from_str(bits[1]) {
                    if pfx.has_routable_prefix_length() {
                        *as_paths_map.entry(as_path).or_insert(0) += 1;
                    }
                }
            }
        }

        Ok(AsPathsSeen(as_paths_map))
    }

    /// Converts this into a set of path segments leading up to and including,
    /// a provider free network (as per presence of an AS0 ASPA object).
    ///
    /// Returns a set to ensure deduplication of segments.
    pub fn segments_to_provider_free(self, aspas: &HashMap<Asn, HashSet<Asn>>) -> HashSet<AsPath> {
        self.0
            .into_iter()
            .flat_map(|(path, _)| path.segment_to_provider_free(aspas))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::inputs::rpki_stats::RpkiStats;

    use super::*;

    #[test]
    fn parse_ris_paths_psv() {
        let path = PathBuf::from("test/ris-routes/ris-routes-short.psv");
        AsPathsSeen::from_ris_psv_file(&path).unwrap();
    }

    #[test]
    fn get_paths_to_no_provider() {
        let path = PathBuf::from("test/ris-routes/ris-routes-short.psv");
        let as_paths = AsPathsSeen::from_ris_psv_file(&path).unwrap();

        let rpki_stats_file = PathBuf::from("test/ris-routes/routinator-short-for-routes.json");
        let rpki_stats = RpkiStats::from_routinator_file(&rpki_stats_file).unwrap();

        let segments = as_paths.segments_to_provider_free(rpki_stats.aspas());

        let mut expected = HashSet::new();
        expected.insert(AsPath(vec![1.into(), 12.into(), 14.into()]));
        expected.insert(AsPath(vec![1.into(), 12.into(), 13.into()]));
        expected.insert(AsPath(vec![1.into(), 13.into(), 14.into()]));
        expected.insert(AsPath(vec![1.into(), 15.into(), 16.into()]));

        assert_eq!(segments, expected);
    }
}
