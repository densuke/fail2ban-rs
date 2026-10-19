//! IP の正規化と ignoreip リストのテスト。

use std::net::IpAddr;

use fail2ban_rs::ip::{IgnoreList, canonical_ip};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn entries(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn canonical_ip_parses_plain_ipv4() {
    assert_eq!(canonical_ip("192.0.2.1"), Some(ip("192.0.2.1")));
}

#[test]
fn canonical_ip_strips_brackets_for_ipv6() {
    assert_eq!(canonical_ip("[2001:db8::1]"), Some(ip("2001:db8::1")));
}

#[test]
fn canonical_ip_maps_ipv4_mapped_ipv6_to_ipv4() {
    assert_eq!(canonical_ip("::ffff:192.0.2.1"), Some(ip("192.0.2.1")));
}

#[test]
fn canonical_ip_rejects_leading_zero_octets() {
    assert_eq!(canonical_ip("192.030.0.6"), None);
}

#[test]
fn canonical_ip_rejects_hostnames() {
    assert_eq!(canonical_ip("example.com"), None);
}

#[test]
fn ignore_list_matches_cidr_and_single_addresses() {
    let list = IgnoreList::parse(&entries(&[
        "127.0.0.1/8",
        "::1",
        "192.168.11.0/24",
        "100.64.0.0/10",
    ]))
    .unwrap();

    assert!(list.contains(ip("127.5.5.5")));
    assert!(list.contains(ip("::1")));
    assert!(list.contains(ip("192.168.11.5")));
    assert!(list.contains(ip("100.84.161.1")));
    assert!(!list.contains(ip("192.0.2.1")));
    assert!(!list.contains(ip("2001:db8::1")));
}

#[test]
fn ignore_list_matches_canonicalized_ipv4_mapped_address() {
    let list = IgnoreList::parse(&entries(&["127.0.0.1/8"])).unwrap();
    let canonical = canonical_ip("::ffff:127.0.0.1");
    assert!(list.contains(canonical.unwrap()));
}

#[test]
fn ignore_list_rejects_invalid_entry() {
    assert!(IgnoreList::parse(&entries(&["not-an-ip"])).is_err());
}

#[test]
fn ignore_list_matches_raw_ipv4_mapped_ipv6_address() {
    let list = IgnoreList::parse(&entries(&["127.0.0.0/8"])).unwrap();
    assert!(list.contains(ip("::ffff:127.0.0.1")));
}

#[test]
fn ignore_list_maps_ipv4_mapped_cidr_to_ipv4() {
    let list = IgnoreList::parse(&entries(&["::ffff:10.0.0.0/104"])).unwrap();
    assert!(list.contains(ip("10.1.2.3")));
    assert!(!list.contains(ip("11.0.0.1")));
}

#[test]
fn ignore_list_matches_single_ipv4_mapped_entry() {
    let list = IgnoreList::parse(&entries(&["::ffff:192.168.11.5"])).unwrap();
    assert!(list.contains(ip("192.168.11.5")));
}

#[test]
fn ignore_list_rejects_ipv4_mapped_cidr_shorter_than_96() {
    assert!(IgnoreList::parse(&entries(&["::ffff:0.0.0.0/80"])).is_err());
}

#[test]
fn canonical_ip_rejects_unpaired_brackets() {
    assert_eq!(canonical_ip("[1.2.3.4"), None);
    assert_eq!(canonical_ip("1.2.3.4]"), None);
}
