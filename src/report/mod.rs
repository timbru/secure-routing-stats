use crate::ip::AsnSet;
use crate::ip::IpResourceSet;

pub mod resources;
pub mod world;

#[derive(Clone, Debug)]
pub struct ScopeLimits {
    ips:  Option<IpResourceSet>,
    asns: Option<AsnSet>,
}

impl ScopeLimits {
    pub fn new(ips: Option<IpResourceSet>, asns: Option<AsnSet>) -> Self {
        ScopeLimits { ips, asns }
    }

    pub fn ips(&self) -> &Option<IpResourceSet> {
        &self.ips
    }

    pub fn asns(&self) -> &Option<AsnSet> {
        &self.asns
    }
}