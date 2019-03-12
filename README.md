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
stats can be found [here](https://www.nro.net/wp-content/uploads/apnic-uploads/delegated-extended).

You can also use your own files of course, e.g. if you want to hypothesise about the impact of
potential announcements and/or roas, as long as you follow the same format. Beware that you will
need to use a value of '5' or higher for the number of RIS peers, otherwise the announcement is
disregarded.


Default output format is json. Example:
```
$ secure_routing_stats world \
      --ris4 test/20190304/riswhoisdump.IPv4 \
      --ris6 test/20190304/riswhoisdump.IPv6 \
      --vrps test/20190304/vrps.csv \
      --delegations test/20190304/delegated-extended.txt 
```

Alternatively this can produce simple text output:
```
$ secure_routing_stats world\
      --ris4 test/20190304/riswhoisdump.IPv4 \
      --ris6 test/20190304/riswhoisdump.IPv6 \
      --vrps test/20190304/vrps.csv \
      --delegations test/20190304/delegated-extended.txt \
      --format text
```


## Resource based reports

Produces a detailed report of the validity of announcements, as well as the 
visibility of Validated ROA Payloads in BGP.

This defaults to all resources when run like this:
```
$ secure_routing_stats resources \
      --ris4 test/20190304/riswhoisdump.IPv4 \
      --ris6 test/20190304/riswhoisdump.IPv6 \
      --vrps test/20190304/vrps.csv \
```

But in practice you will want to scope this report to specific IP resources, 
using the ```--ips``` option, or ASNs, using the ```--asns``` option. And, you
can also have text output:

Examples:
```
$ secure_routing_stats resources \
      --ris4 test/20190304/riswhoisdump.IPv4 \
      --ris6 test/20190304/riswhoisdump.IPv6 \
      --vrps test/20190304/vrps.csv \
      --ips "185.49.140.0/22, 2a04:b900::/29" \
      --format text
```

```
$ secure_routing_stats resources \
      --ris4 test/20190304/riswhoisdump.IPv4 \
      --ris6 test/20190304/riswhoisdump.IPv6 \
      --vrps test/20190304/vrps.csv \
      --asns "AS199664, AS199665-AS199666"
```

## Running as an HTTP daemon

Finally, you have the option of running the stats as an HTTP daemon. The 
application will read files at startup, and from there on you can use the 
UI/API to look at a worldmap of country stats, and to do queries about
specific IP prefixes (or ranges) and/or ASNs.

We have a public instance of this running [here](https://nlnetlabs.nl/projects/rpki/rpki-analytics/)

You can run this locally:
```
$ secure_routing_stats daemon \
      --ris4 test/20190304/riswhoisdump.IPv4 \
      --ris6 test/20190304/riswhoisdump.IPv6 \
      --vrps test/20190304/vrps.csv \
      --delegations test/20190304/delegated-extended.txt 
```

The server will bind to port 8080, or die trying.

## Future Work

In future we hope to extend the functionality with a number of things, like:
* Automatically re-read input data (configurable, with defaults)
* See the effect of excpections or ROAs that you may want to create
* Historical analysis - what was the state on date X?
* Historical analysis - what is the history of announcements and validatity given an IP prefix or ASN

