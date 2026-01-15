//! Parse Routinator Stats output.
//!
//! For now, this is the quickest option. In time, this should probably be
//! replaced by something that parses CCR output.

use crate::inputs::{asn::Asn, ip::IpPrefix};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RoutinatorStatsJson {
    pub metadata: Metadata,
    pub roas: Vec<RoaJson>,
    pub aspas: Vec<AspaJson>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Metadata {
    /// Unix timestamp of file generation
    pub generated: i64,
    // generatedTime can be ignored, it's a UTC string notation of the same time
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoaJson {
    pub asn: Asn,
    pub prefix: IpPrefix,
    pub max_length: u8,
    pub ta: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AspaJson {
    pub customer: Asn,
    pub providers: Vec<Asn>,
    pub ta: String,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parse_json() {
        let json =
            include_str!("../../test/20250112/routinator-shortened.json");
        let stats: RoutinatorStatsJson = serde_json::from_str(json).unwrap();
        assert_eq!(12, stats.roas.len());
        assert_eq!(15, stats.aspas.len());
    }
}
