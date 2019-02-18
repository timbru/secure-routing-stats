//! Parse delegated extended stats

use crate::ip::{
    IpRange
};


enum Source {
    Iana,
    Afrinic,
    Apnic,
    Arin,
    Lacnic,
    RipeNcc
}

struct Delegation {
    source: Source,
    country: String,
    range: IpRange
}




