//! Parse Routinator JSON output.
//!
//! For now, this is the quickest option. In time, this should probably be
//! replaced by something that parses CCR output.

use crate::ip::{Asn, IpPrefix};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RoutinatorJson {
    metadata: Metadata,
    roas: Vec<RoaJson>,
    aspas: Vec<AspaJson>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Metadata {
    /// Unix timestamp of file generation
    generated: usize,
    // generatedTime can be ignored, it's a UTC string notation of the same time
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoaJson {
    asn: Asn,
    prefix: IpPrefix,
    max_length: u128,
    ta: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AspaJson {
    customer: Asn,
    providers: Vec<Asn>,
    ta: String,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parse_json() {
        let json = include_str!("../test/20250112/routinator-shortened.json");
        let stats: RoutinatorJson = serde_json::from_str(json).unwrap();
        assert_eq!(12, stats.roas.len());
        assert_eq!(15, stats.aspas.len());
    }
}
