# Secure Routing Statistics

This code is intended to help analyse the quality or RPKI ROAs vs BGP.

Similar to these stats, which Tim created in a previous employment:
https://lirportal.ripe.net/certification/content/static/statistics/world-roas.html

This is still work in progress, and needs some more testing. But, we
believe this is now mature enough to develop in the open.

## Getting Started

### Rust

While some system distributions include Rust as system packages, we rely on a
relatively new version of Rust. We therefore suggest to use the canonical 
Rust installation via a tool called rustup.

To install rustup and Rust, simply do:
```
curl https://sh.rustup.rs -sSf | sh
```
Alternatively, get the file, have a look and then run it manually. Follow the instructions to get rustup and cargo, the rust build tool, into your path.

You can update your Rust installation later by simply running:
```
rustup update 
```

### C Tool Chain

Some of the libraries may require a C toolchain to be present. Your system 
probably has some easy way to install the minimum set of packages to build 
from C sources. If you are unsure, try to run ```cc``` on a command line and if 
there’s a complaint about missing input files, you are probably good to go.

### Build

Checkout this source code and then make a release binary:

```
cargo build --release
```

This takes some time, especially the first time when it also compiles all the
dependencies of this code. But the resulting binary is much faster. And you 
really want this binary to be fast when you process 800k announcements.

For reference doing a full report of invalids, discarding the output of 
course so as to obtain some even more flattering stats, takes 1.8 seconds on 
a 2017 mac book pro (i7 3.1GHz).

## Per country stats

Produces a report of totals for valid, invalid asn, invalid length and not 
found announcements per country, organised by country code. Also includes an
overall total (using the key 'all'). As input this needs three files:
* RIS style dump file
* roas.csv
* NRO delegated extended statistics

Default output format is json. Example:
```
$ ./target/release/main world \
      --dump test/20181017/riswhoisdump.IPv4 \
      --roas test/20181017/export-roa.csv \
      --stats test/20181017/delegated-extended.txt 
```

Alternatively this can produce an world map html file. Example:
```
$ ./target/release/main world \
      --dump test/20181017/riswhoisdump.IPv4 \
      --roas test/20181017/export-roa.csv \
      --stats test/20181017/delegated-extended.txt
      --format html
```

## Invalids reports

Produces a detailed report of invalids for some address space. Defaults to all
address space, but can be scoped to a smaller set. Sets are defined as comma 
separated prefixes and/or ranges.

Example:
```
$ ./target/release/main invalids \
      --dump test/20181017/riswhoisdump.IPv4 \
      --roas test/20181017/export-roa.csv \
      --scope "193.0.0.0/8,194.0.0.0-194.0.1.3"
```