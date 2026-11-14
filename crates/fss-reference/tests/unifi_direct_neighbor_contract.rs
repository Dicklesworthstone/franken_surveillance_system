#![forbid(unsafe_code)]
//! Scoped cached-neighbor hints are bounded, unauthenticated discovery inputs.
use fss_reference::unifi_direct::discovery::neighbor::{self, Error, Scope};
use std::{collections::BTreeSet, net::Ipv4Addr};

#[test]
fn cached_neighbors_are_scoped_deduplicated_and_batched_without_loss() {
    let scope = Scope::new(Ipv4Addr::new(192, 168, 4, 1), 22, 10001).unwrap();
    let input = "IP address HW type Flags HW address Mask Device\n\
192.168.4.2 0x1 0x2 aa * eth0\n\
192.168.4.2 0x1 0x2 aa * eth0\n\
192.168.4.3 0x1 0x0 aa * eth0\n\
192.168.4.4 0x1 0x2 aa * eth1\n\
192.168.8.5 0x1 0x2 aa * eth0\n";
    assert_eq!(
        neighbor::parse(input, "eth0", scope).unwrap(),
        [Ipv4Addr::new(192, 168, 4, 2)]
    );
    assert!(neighbor::parse("IP address\ninvalid\n", "eth0", scope).is_err());
    assert!(neighbor::parse(input, "../eth0", scope).is_err());
    assert_eq!(
        neighbor::parse(&"x".repeat(128 * 1024 + 1), "eth0", scope).unwrap_err(),
        Error::Limit
    );
    let hosts: Vec<_> = (2_u32..=131)
        .map(|n| Ipv4Addr::from(u32::from(Ipv4Addr::new(192, 168, 4, 0)) + n))
        .collect();
    let windows = neighbor::plans(scope, &hosts, Some(hosts[0])).unwrap();
    assert_eq!(windows.len(), 3);
    assert!(windows.iter().all(|w| w.len() <= 64));
    let unique: BTreeSet<_> = windows
        .iter()
        .flat_map(|w| w.iter().skip(2).map(|x| *x.ip()))
        .collect();
    assert_eq!(unique.len(), hosts.len());
    let too_many: Vec<_> = (2_u32..=250)
        .map(|n| Ipv4Addr::from(u32::from(Ipv4Addr::new(192, 168, 4, 0)) + n))
        .collect();
    assert_eq!(
        neighbor::plans(scope, &too_many, None).unwrap_err(),
        Error::Limit
    );
    assert!(neighbor::plans(scope, &[], Some(Ipv4Addr::new(192, 168, 8, 1))).is_err());
    assert!(Scope::new(Ipv4Addr::new(8, 8, 8, 8), 24, 10001).is_err());
}

#[test]
fn complete_subnet_must_stay_within_one_local_address_range() {
    for (address, prefix) in [
        (Ipv4Addr::new(10, 4, 0, 1), 8),
        (Ipv4Addr::new(172, 16, 0, 1), 12),
        (Ipv4Addr::new(192, 168, 4, 1), 16),
        (Ipv4Addr::new(169, 254, 2, 1), 16),
    ] {
        assert!(Scope::new(address, prefix, 10001).is_ok());
        assert_eq!(
            Scope::new(address, prefix - 1, 10001).unwrap_err(),
            Error::Configuration
        );
    }
}
