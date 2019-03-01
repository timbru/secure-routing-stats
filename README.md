[![Travis Build Status](https://travis-ci.com/NLnetLabs/secure-routing-stats.svg?branch=master)](https://travis-ci.com/NLnetLabs/secure-routing-stats)

# Secure Routing Statistics

Analyse the quality of RPKI ROAs vs BGP.

If you have any feedback, we would love to hear from you. Don’t hesitate to
[create an issue on Github](https://github.com/NLnetLabs/secure-routing-stats/issues/new)
or post a message on our [RPKI mailing list](https://nlnetlabs.nl/mailman/listinfo/rpki). 
You can lean more about Routinator and RPKI technology by reading our documentation on 
[Read the Docs](https://rpki.readthedocs.io/).

## Getting Started

### Rust

While some system distributions include Rust as system packages, we rely on a
Rust version 1.31 or newer. We therefore suggest to use the canonical Rust
installation via a tool called rustup.

To install rustup and Rust, simply do:
```
curl https://sh.rustup.rs -sSf | sh
```

Note that this will also add your ```$HOME/.cargo/bin``` to your ```$PATH``` 
and profile, allowing to find Rust commands such as ```cargo```, ```rustc``` 
and ```rustup```. Furthermore this is where the ```cargo install``` command 
will put binaries that you build locally.

Alternatively, get the file, have a look and then run it manually. Follow the
instructions to get rustup and cargo, the rust build tool, into your path.

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
cargo install --force
```

The ```--force``` flag is not needed the first time you install this, but if 
you had installed a previous version, this will ensure that it's updated. So,
 we recommend that you just use ```--force``` here. 

## Per country stats

Produces a report of totals for valid, invalid asn, invalid length and not 
found announcements per country, organised by country code. Also includes an
overall total (using the key 'all'). As input this needs three files:
* RIS style dump file
* roas.csv
* NRO delegated extended statistics

RIS dump files may be found [here](http://www.ris.ripe.net/dumps/). The roas.csv format of either
[routinator](https://github.com/NLnetLabs/routinator) or 
[RIPE NCC RPKI Validator](https://github.com/ripE-NCC/rpki-validator-3) are supported. Delegated
stats can be found [here]((https://www.nro.net/wp-content/uploads/apnic-uploads/delegated-extended).

You can also use your own files of course, e.g. if you want to hypothesise about the impact of
potential announcements and/or roas, as long as you follow the same format. Beware that you will
need to use a value of '5' or higher for the number of RIS peers, otherwise the announcement is
disregarded.


Default output format is json. Example:
```
$ ./target/release/secure_routing_stats world \
      --dump test/20181017/riswhoisdump.IPv4 \
      --roas test/20181017/export-roa.csv \
      --stats test/20181017/delegated-extended.txt 
```

Alternatively this can produce an world map html file. Example:
```
$ ./target/release/secure_routing_stats world \
      --dump test/20181017/riswhoisdump.IPv4 \
      --roas test/20181017/export-roa.csv \
      --stats test/20181017/delegated-extended.txt
      --format html
```

Finally, you can also get a simple text output:
```
$ ./target/release/secure_routing_stats world \
      --dump test/20181017/riswhoisdump.IPv4 \
      --roas test/20181017/export-roa.csv \
      --stats test/20181017/delegated-extended.txt
      --format text
```


## Invalids reports

Produces a detailed report of invalids for some address space. Defaults to all
address space, but can be scoped to a smaller set. Sets are defined as comma 
separated prefixes and/or ranges.

Example:
```
$ ./target/release/secure_routing_stats invalids \
      --dump test/20181017/riswhoisdump.IPv4 \
      --roas test/20181017/export-roa.csv \
      --scope "193.0.0.0/8,194.0.0.0-194.0.1.3"
```

By default this produces JSON output. But you can use ```--format text``` to 
get a human readable report.


## Validated ROA Payloads seen

Produces a report of Validated ROA Payloads (VRPs) visibility in BGP. VRPs 
for which at least one valid announcement exists are considered 'seen'. Note 
that a single VRP may have many valid announcements, because of max length. 
VRPs for which no valid announcements are seen, are considered 'unseen'. 

If a VRP is 'unseen', this may be because these VRPs are stale, e.g. they are
no longer needed. But, it may also be that these VRPs serve to authorise 
back-up or future announcements.   

Example:
```
$ ./target/release/secure_routing_stats seen \
      --dump test/20181017/riswhoisdump.IPv4 \
      --roas test/20181017/export-roa.csv \
      --scope "193.0.0.0/8,194.0.0.0-194.0.1.3"
```
