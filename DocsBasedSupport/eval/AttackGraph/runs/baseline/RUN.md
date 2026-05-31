# AttackGraph run: `baseline`

This folder collects the outputs of one experiment over the MITRE ATT&CK
knowledge graph. Each section below records a script that was run into
this folder, including parameters and the files it produced. The folder
is self-contained: copy / archive / commit it to keep the experiment
reproducible.


## load_attack.py
- `timestamp_utc`: `2026-05-31T09:02:41+00:00`
- `bundle_path`: `/Users/bkosinski/Desktop/STUDIA/MGR/SecSearch/DocsBasedSupport/data/ontologies/mitre_attack/enterprise-attack.json`
- `bundle_url`: `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
- `enrich`: `true`
- `reset`: `true`
- `source_id`: `mitre-attack:enterprise`
- `outputs`: `load_summary.json`

## eval_link_prediction.py
- `timestamp_utc`: `2026-05-31T09:03:09+00:00`
- `hold_out_fraction`: `0.2`
- `max_actors`: `null`
- `num_candidates`: `697`
- `num_evaluated_actors`: `150`
- `num_held_out_edges`: `909`
- `num_total_edges`: `4546`
- `seed`: `20260529`
- `top_ks`: `5, 10, 20, 50`
- `outputs`: `link_prediction.json`

## community_report.py
- `timestamp_utc`: `2026-05-31T09:03:11+00:00`
- `community_property`: `community`
- `enriched_node_count`: `1840`
- `pagerank_property`: `pagerank`
- `top_communities`: `10`
- `top_overall`: `30`
- `top_per_community`: `10`
- `top_per_label`: `15`
- `total_communities`: `30`
- `outputs`: `community_report.json`

## eval_cve_apt.py
- `timestamp_utc`: `2026-05-31T09:03:17+00:00`
- `coverage_fraction`: `0.5758`
- `max_hops`: `3`
- `max_paths_per_pair`: `10`
- `num_cves`: `33`
- `num_cves_with_actor_link`: `19`
- `pagerank_property`: `pagerank`
- `top_actors`: `5`
- `variant`: `baseline`
- `outputs`: `cve_apt_paths_baseline.json`
