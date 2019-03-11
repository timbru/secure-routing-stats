extern crate actix_web;
extern crate core;
extern crate clap;
#[macro_use] extern crate derive_more;
extern crate futures;
extern crate intervaltree;
#[macro_use] extern crate serde_derive;
extern crate serde;
extern crate serde_json;

#[macro_use] pub mod statics;
pub mod announcements;
pub mod delegations;
pub mod ip;
pub mod report;
pub mod server;
pub mod validation;
pub mod vrps;
