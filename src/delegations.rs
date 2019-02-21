//! Parse delegated extended stats
use std::str::FromStr;
use crate::ip::{
    IpRange
};


//------------ Registry -----------------------------------------------------

#[derive(Clone, Debug)]
pub enum Registry {
    Iana,
    Afrinic,
    Apnic,
    Arin,
    Lacnic,
    RipeNcc
}

impl FromStr for Registry {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        unimplemented!()
    }
}


#[derive(Clone, Debug)]
pub struct Delegation {
    source: Registry,
    country: String,
    range: IpRange
}






