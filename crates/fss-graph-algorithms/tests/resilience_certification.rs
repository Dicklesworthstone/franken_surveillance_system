#![forbid(unsafe_code)]
//! Certification of `ALG-RELIABILITY-001` and `ALG-INTERDICT-001`: blindness probability
//! bounds against a direct scenario sum (and their containment of every probability vector
//! inside the declared intervals), minimal cut sets against exhaustive minimality, and minimum
//! interdictions against brute-force sensor subsets, with witness walks checked for validity.

mod common;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use common::{Rng, TestResult, assert_registered, certify, registered};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::interdiction::{self, InterdictionOutcome, InterdictionQuery};
use fss_graph_algorithms::reliability::{self, DomainSpec, ONE_E18, ReliabilityModel};
use fss_graph_algorithms::weighted::{Orientation, WeightedGraph, WeightedGraphBuilder};

fn random_model(seed: u64) -> TestResult<ReliabilityModel> {
    let mut rng = Rng(seed ^ 0x7e11_ab1e);
    let sensors: Vec<String> = (0..1 + rng.below(5)).map(|i| format!("cam-{i}")).collect();
    let zones: Vec<(String, Vec<String>)> = (0..1 + rng.below(4))
        .map(|z| {
            let observers = sensors
                .iter()
                .filter(|_| rng.chance(450))
                .cloned()
                .collect();
            (format!("zone-{z}"), observers)
        })
        .collect();
    // Domains may only name sensors that observe some zone (the model refuses unknown members).
    let observing: BTreeSet<String> = zones
        .iter()
        .flat_map(|(_, obs)| obs.iter().cloned())
        .collect();
    let sensors: Vec<String> = sensors
        .into_iter()
        .filter(|s| observing.contains(s))
        .collect();
    let mut domains = Vec::new();
    for (i, sensor) in sensors.iter().enumerate() {
        if rng.chance(800) {
            let lo = (rng.next() % 300_000) as u32;
            domains.push(DomainSpec {
                id: format!("camera:{i}"),
                lo_ppm: lo,
                hi_ppm: lo + (rng.next() % 200_000) as u32,
                members: BTreeSet::from([sensor.clone()]),
            });
        }
    }
    for d in 0..rng.below(3) {
        let members: BTreeSet<String> = sensors
            .iter()
            .filter(|_| rng.chance(500))
            .cloned()
            .collect();
        if members.is_empty() {
            continue;
        }
        let lo = (rng.next() % 100_000) as u32;
        domains.push(DomainSpec {
            id: format!("power:circuit-{d}"),
            lo_ppm: lo,
            hi_ppm: lo + (rng.next() % 50_000) as u32,
            members,
        });
    }
    Ok(ReliabilityModel::new(&zones, &domains)?)
}

/// `P(blind)` of `zone` with every domain failing with probability `p[domain]` (f64).
fn blind_probability(model: &ReliabilityModel, zone: &str, p: &[f64]) -> f64 {
    let observers = &model.zones()[zone];
    let domains = model.domains();
    let k = domains.len();
    let mut total = 0.0;
    for mask in 0_u32..(1 << k) {
        let down = |sensor: &String| {
            (0..k).any(|d| mask & (1 << d) != 0 && domains[d].members.contains(sensor))
        };
        if observers.iter().all(down) {
            let mut probability = 1.0;
            for (d, &failure) in p.iter().enumerate().take(k) {
                probability *= if mask & (1 << d) != 0 {
                    failure
                } else {
                    1.0 - failure
                };
            }
            total += probability;
        }
    }
    total
}

#[test]
fn blindness_bounds_contain_every_admissible_probability() -> TestResult {
    for seed in 0..1_500_u64 {
        let model = random_model(seed)?;
        let links = model.links() as u64;
        let k = model.domains().len() as u64;
        let bound = reliability::bound(model.zones().len() as u64, links, k);
        let run = reliability::reliability_bounds(&model, registered(&bound))?;
        let mut rng = Rng(seed);
        for zone in &run.output.zones {
            let (lo, hi) = zone.blind_probability_e18;
            assert!(lo <= hi && hi <= ONE_E18, "seed {seed}");
            let domains = model.domains();
            let mut vectors = vec![
                domains
                    .iter()
                    .map(|d| f64::from(d.lo_ppm) / 1e6)
                    .collect::<Vec<_>>(),
                domains
                    .iter()
                    .map(|d| f64::from(d.hi_ppm) / 1e6)
                    .collect::<Vec<_>>(),
            ];
            for _ in 0..4 {
                vectors.push(
                    domains
                        .iter()
                        .map(|d| {
                            let span = u64::from(d.hi_ppm - d.lo_ppm) + 1;
                            f64::from(d.lo_ppm + (rng.next() % span) as u32) / 1e6
                        })
                        .collect(),
                );
            }
            for p in &vectors {
                let truth = blind_probability(&model, &zone.zone, p);
                assert!(
                    lo as f64 / 1e18 <= truth + 1e-12 && truth - 1e-12 <= hi as f64 / 1e18,
                    "seed {seed} zone {}: {truth} outside [{lo}, {hi}]",
                    zone.zone
                );
            }
            // Minimal cuts: exhaustive minimality over the relevant domains.
            let observers = &model.zones()[&zone.zone];
            let relevant: Vec<&DomainSpec> = domains
                .iter()
                .filter(|d| zone.relevant_domains.contains(&d.id))
                .collect();
            let blind = |set: &BTreeSet<&str>| {
                observers.iter().all(|sensor| {
                    relevant
                        .iter()
                        .any(|d| set.contains(d.id.as_str()) && d.members.contains(sensor))
                }) || observers.is_empty()
            };
            let mut expected: Vec<Vec<String>> = Vec::new();
            for mask in 1_u32..(1 << relevant.len()) {
                let set: BTreeSet<&str> = (0..relevant.len())
                    .filter(|b| mask & (1 << b) != 0)
                    .map(|b| relevant[b].id.as_str())
                    .collect();
                if blind(&set)
                    && set.iter().all(|d| {
                        let mut smaller = set.clone();
                        smaller.remove(d);
                        !blind(&smaller)
                    })
                {
                    expected.push(set.iter().map(|s| (*s).to_owned()).collect());
                }
            }
            expected.sort_by(|a, b| (a.len(), a).cmp(&(b.len(), b)));
            let got: Vec<Vec<String>> = zone
                .minimal_cuts
                .iter()
                .map(|c| c.domains.clone())
                .collect();
            assert_eq!(got, expected, "seed {seed} zone {}", zone.zone);
            assert_eq!(zone.minimal_cut_count, expected.len() as u64);
        }
        if seed % 50 == 0 {
            certify(&run, &reliability::IDENTITY, &bound, |budget| {
                reliability::reliability_bounds(&model, budget)
            })?;
        }
    }
    Ok(())
}

#[test]
fn reliability_textbook_case() -> TestResult {
    // Two cameras on one circuit watch the porch: losing the circuit blinds it, losing one
    // camera does not.
    let zones = vec![
        (
            "porch".to_owned(),
            vec!["cam-a".to_owned(), "cam-b".to_owned()],
        ),
        ("shed".to_owned(), vec![]),
    ];
    let domains = vec![
        DomainSpec {
            id: "camera:a".into(),
            lo_ppm: 10_000,
            hi_ppm: 20_000,
            members: BTreeSet::from(["cam-a".to_owned()]),
        },
        DomainSpec {
            id: "camera:b".into(),
            lo_ppm: 10_000,
            hi_ppm: 20_000,
            members: BTreeSet::from(["cam-b".to_owned()]),
        },
        DomainSpec {
            id: "power:c3".into(),
            lo_ppm: 1_000,
            hi_ppm: 5_000,
            members: BTreeSet::from(["cam-a".to_owned(), "cam-b".to_owned()]),
        },
    ];
    let model = ReliabilityModel::new(&zones, &domains)?;
    let run = reliability::reliability_bounds(&model, Budget::new(1 << 20, 1 << 20))?;
    let porch = &run.output.zones[0];
    let cuts: Vec<Vec<String>> = porch
        .minimal_cuts
        .iter()
        .map(|c| c.domains.clone())
        .collect();
    assert_eq!(
        cuts,
        vec![
            vec!["power:c3".to_owned()],
            vec!["camera:a".to_owned(), "camera:b".to_owned()]
        ]
    );
    // P = c + (1 - c) a b: at lo 0.001 + 0.999 * 1e-4 = 0.0010999.
    let (lo, hi) = porch.blind_probability_e18;
    assert!(lo <= 1_099_900_000_000_000 && 1_099_900_000_000_000 <= lo + 1_000);
    assert!(hi >= 5_398_000_000_000_000);
    let shed = &run.output.zones[1];
    assert_eq!(shed.blind_probability_e18, (ONE_E18, ONE_E18));
    Ok(())
}

fn site(seed: u64) -> TestResult<(WeightedGraph, InterdictionQuery)> {
    let mut rng = Rng(seed ^ 0x1d7e);
    let n = 2 + rng.below(6);
    let orientation = if rng.chance(500) {
        Orientation::Directed
    } else {
        Orientation::Undirected
    };
    let mut builder = WeightedGraphBuilder::new(orientation, "steps");
    let zones: Vec<String> = (0..n).map(|z| format!("z{z}")).collect();
    for zone in &zones {
        builder.add_node(zone.clone());
    }
    let mut pairs = BTreeSet::new();
    for a in 0..n {
        for b in 0..n {
            if a != b && rng.chance(350) {
                let key = if orientation == Orientation::Undirected {
                    (a.min(b), a.max(b))
                } else {
                    (a, b)
                };
                pairs.insert(key);
            }
        }
    }
    for (a, b) in pairs {
        builder.add_arc(zones[a].clone(), zones[b].clone(), 1);
    }
    let sensors: Vec<String> = (0..1 + rng.below(6)).map(|s| format!("cam-{s}")).collect();
    let mut observers = BTreeMap::new();
    for zone in &zones {
        let set: BTreeSet<String> = sensors
            .iter()
            .filter(|_| rng.chance(400))
            .cloned()
            .collect();
        observers.insert(zone.clone(), set);
    }
    let costs = sensors
        .iter()
        .map(|s| (s.clone(), 1 + rng.next() % 4))
        .collect();
    let entries = BTreeSet::from([zones[0].clone()]);
    let targets = BTreeSet::from([zones[n - 1].clone()]);
    Ok((
        builder.build()?,
        InterdictionQuery {
            observers,
            costs,
            entries,
            targets,
        },
    ))
}

fn open_walk(graph: &WeightedGraph, query: &InterdictionQuery, disabled: &BTreeSet<&str>) -> bool {
    let open = |zone: &str| {
        query
            .observers
            .get(zone)
            .is_none_or(|obs| obs.iter().all(|s| disabled.contains(s.as_str())))
    };
    let mut seen = BTreeSet::new();
    let mut queue: VecDeque<String> = query.entries.iter().filter(|z| open(z)).cloned().collect();
    seen.extend(queue.iter().cloned());
    while let Some(zone) = queue.pop_front() {
        if query.targets.contains(&zone) {
            return true;
        }
        let node = graph.index_of(&zone).unwrap_or(0);
        for &arc in graph.out_arcs(node) {
            let next = match graph.orientation() {
                Orientation::Directed => graph.arc(arc).head,
                Orientation::Undirected => graph.arc(arc).other(node),
            };
            let id = graph.id(next).to_owned();
            if open(&id) && seen.insert(id.clone()) {
                queue.push_back(id);
            }
        }
    }
    false
}

#[test]
fn interdiction_equals_brute_force_subsets() -> TestResult {
    let mut kinds = BTreeMap::new();
    for seed in 0..2_000_u64 {
        let (graph, query) = site(seed)?;
        let sensors: Vec<String> = query.costs.keys().cloned().collect();
        let relevant: Vec<&String> = sensors
            .iter()
            .filter(|s| query.observers.values().any(|obs| obs.contains(*s)))
            .collect();
        let bound = interdiction::bound(
            graph.node_count() as u64,
            graph.arc_count() as u64,
            relevant.len() as u64,
        );
        let run = interdiction::interdiction(&graph, &query, registered(&bound))?;
        let reachable = open_walk(
            &graph,
            &InterdictionQuery {
                observers: BTreeMap::new(),
                ..query.clone()
            },
            &BTreeSet::new(),
        );
        let mut best: Option<(u64, usize, Vec<&String>)> = None;
        for mask in 0_u32..(1 << relevant.len()) {
            let chosen: Vec<&String> = (0..relevant.len())
                .filter(|b| mask & (1 << b) != 0)
                .map(|b| relevant[b])
                .collect();
            let disabled: BTreeSet<&str> = chosen.iter().map(|s| s.as_str()).collect();
            let cost: u64 = chosen.iter().map(|s| query.costs[*s]).sum();
            if open_walk(&graph, &query, &disabled) {
                let key = (cost, chosen.len(), chosen.clone());
                if best.as_ref().is_none_or(|b| key < *b) {
                    best = Some(key);
                }
            }
        }
        let kind = match (&run.output.outcome, best) {
            (InterdictionOutcome::Unreachable, None) => {
                assert!(!reachable, "seed {seed}");
                "unreachable"
            }
            (InterdictionOutcome::BlindPath { path }, Some((0, 0, _))) => {
                assert!(path.first().is_some_and(|z| query.entries.contains(z)));
                "blind"
            }
            (
                InterdictionOutcome::Interdiction {
                    sensors,
                    cost,
                    path,
                    exact,
                },
                Some((best_cost, _, best_set)),
            ) => {
                assert!(*exact);
                assert_eq!(*cost, best_cost, "seed {seed}");
                assert_eq!(sensors.iter().collect::<Vec<_>>(), best_set, "seed {seed}");
                // The witness walk is unobserved once the sensors are disabled.
                let disabled: BTreeSet<&str> = sensors.iter().map(String::as_str).collect();
                for zone in path {
                    assert!(
                        query.observers[zone]
                            .iter()
                            .all(|s| disabled.contains(s.as_str())),
                        "seed {seed}"
                    );
                }
                for pair in path.windows(2) {
                    let (a, b) = (graph.require(&pair[0])?, graph.require(&pair[1])?);
                    assert!(
                        graph.find_arc(a, b).is_some(),
                        "seed {seed}: walk step without an arc"
                    );
                }
                "interdiction"
            }
            (outcome, best) => {
                return Err(format!("seed {seed}: {outcome:?} vs brute force {best:?}").into());
            }
        };
        *kinds.entry(kind).or_insert(0) += 1;
        if seed % 50 == 0 {
            certify(&run, &interdiction::IDENTITY, &bound, |budget| {
                interdiction::interdiction(&graph, &query, budget)
            })?;
        }
    }
    for kind in ["unreachable", "blind", "interdiction"] {
        assert!(kinds.get(kind).copied().unwrap_or(0) > 50, "{kinds:?}");
    }
    Ok(())
}

#[test]
fn implemented_identities_equal_their_machine_registry_rows() -> TestResult {
    assert_registered(&reliability::IDENTITY)?;
    assert_registered(&interdiction::IDENTITY)?;
    Ok(())
}
