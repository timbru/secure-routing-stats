extern crate clap;
extern crate secure_routing_stats;

use std::path::PathBuf;
use secure_routing_stats::announcements::Announcement;
use secure_routing_stats::announcements::RisAnnouncements;
use secure_routing_stats::delegations::IpDelegations;
use secure_routing_stats::roas::Roas;
use secure_routing_stats::ip::IpRangeTree;
use secure_routing_stats::roas::ValidatedRoaPrefix;
use secure_routing_stats::delegations::IpDelegation;
use secure_routing_stats::validation::ValidatedAnnouncement;
use secure_routing_stats::report::CountryStats;


fn main() {

    let announcements: IpRangeTree<Announcement> = RisAnnouncements::from_file(
        &PathBuf::from("test/20181017/riswhoisdump.IPv4")
    ).unwrap();

    let roas: IpRangeTree<ValidatedRoaPrefix> = Roas::from_file(
        &PathBuf::from("test/20181017/export-roa.csv")
    ).unwrap();

    let delegations: IpRangeTree<IpDelegation> = IpDelegations::from_file(
        &PathBuf::from("test/20181017/delegated-extended.txt")
    ).unwrap();

    /*

    Loop over all announcements, and build stats:

    - Validate announcement compared to relevant ROAs
    - Find country for announcement
    - Add to country stats

    */
    let mut country_stats = CountryStats::default();

    for el in announcements.inner().iter() {
        for ann in el.value.iter() {

            let matching_roas = roas.matching_or_less_specific(ann.as_ref());
            let validated = ValidatedAnnouncement::create(ann, &matching_roas);

            let matching_delegations = delegations.matching_or_less_specific(ann.as_ref());

            let cc = match matching_delegations.first() {
                Some(delegation) => &delegation.cc(),
                None => "XX"
            };

            country_stats.add(&validated, cc);
        }
    }

    println!("{:?}", country_stats);
}
