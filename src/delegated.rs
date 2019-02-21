//! Parse delegated extended stats

use crate::ip::{
    IpRange
};

#[derive(Clone, Debug)]
pub enum Source {
    Iana,
    Afrinic,
    Apnic,
    Arin,
    Lacnic,
    RipeNcc
}

#[derive(Clone, Debug)]
pub struct Delegation {
    source: Source,
    country: String,
    range: IpRange
}




