# AttackGraph run: `2026-05-31_enriched_gpt-oss:20b`

This folder collects the outputs of one experiment over the MITRE ATT&CK
knowledge graph. Each section below records a script that was run into
this folder, including parameters and the files it produced. The folder
is self-contained: copy / archive / commit it to keep the experiment
reproducible.


## enrich_with_llm.py
- `timestamp_utc`: `2026-05-31T09:23:34+00:00`
- `dropped_unquoted`: `0`
- `force`: `false`
- `labels`: `ThreatActor, Malware, Tool, Campaign`
- `limit`: `null`
- `model`: `gpt-oss:20b-cloud`
- `new_cve_nodes`: `0`
- `new_exploits_edges`: `8`
- `parse_failures`: `3`
- `processed_entities`: `1051`
- `provider`: `ollama`
- `source_id`: `mitre-attack:enterprise`
- `outputs`: `llm_enrichment.json`

## load_attack.py
- `timestamp_utc`: `2026-05-31T09:25:10+00:00`
- `bundle_path`: `/Users/bkosinski/Desktop/STUDIA/MGR/SecSearch/DocsBasedSupport/data/ontologies/mitre_attack/enterprise-attack.json`
- `bundle_url`: `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
- `enrich`: `true`
- `reset`: `false`
- `source_id`: `mitre-attack:enterprise`
- `outputs`: `load_summary.json`

## eval_cve_apt.py
- `timestamp_utc`: `2026-05-31T09:25:21+00:00`
- `coverage_fraction`: `0.5758`
- `max_hops`: `3`
- `max_paths_per_pair`: `10`
- `num_cves`: `33`
- `num_cves_with_actor_link`: `19`
- `pagerank_property`: `pagerank`
- `top_actors`: `5`
- `variant`: `enriched`
- `outputs`: `cve_apt_paths_enriched.json`

## eval_cve_apt.py
- `timestamp_utc`: `2026-05-31T09:30:46+00:00`
- `coverage_fraction`: `0.6364`
- `max_hops`: `3`
- `max_paths_per_pair`: `10`
- `num_cves`: `33`
- `num_cves_with_actor_link`: `21`
- `pagerank_property`: `pagerank`
- `top_actors`: `5`
- `variant`: `enriched`
- `outputs`: `cve_apt_paths_enriched.json`

## load_attack.py
- `timestamp_utc`: `2026-05-31T09:38:29+00:00`
- `bundle_path`: `/Users/bkosinski/Desktop/STUDIA/MGR/SecSearch/DocsBasedSupport/data/ontologies/mitre_attack/enterprise-attack.json`
- `bundle_url`: `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
- `enrich`: `true`
- `reset`: `false`
- `source_id`: `mitre-attack:enterprise`
- `outputs`: `load_summary.json`

## enrich_with_llm.py
- `timestamp_utc`: `2026-05-31T09:40:50+00:00`
- `dropped_unmatched_actors`: `28`
- `dropped_unquoted`: `0`
- `force`: `true`
- `labels`: `Campaign`
- `limit`: `null`
- `model`: `gpt-oss:20b-cloud`
- `new_attribution_edges`: `13`
- `new_cve_nodes`: `0`
- `new_exploits_edges`: `0`
- `parse_failures`: `0`
- `processed_entities`: `56`
- `provider`: `ollama`
- `source_id`: `mitre-attack:enterprise`
- `outputs`: `llm_enrichment.json`

## load_attack.py
- `timestamp_utc`: `2026-05-31T09:41:13+00:00`
- `bundle_path`: `/Users/bkosinski/Desktop/STUDIA/MGR/SecSearch/DocsBasedSupport/data/ontologies/mitre_attack/enterprise-attack.json`
- `bundle_url`: `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
- `enrich`: `true`
- `reset`: `false`
- `source_id`: `mitre-attack:enterprise`
- `outputs`: `load_summary.json`

## eval_cve_apt.py
- `timestamp_utc`: `2026-05-31T09:41:13+00:00`
- `coverage_fraction`: `0.7879`
- `max_hops`: `3`
- `max_paths_per_pair`: `10`
- `num_cves`: `33`
- `num_cves_with_actor_link`: `26`
- `pagerank_property`: `pagerank`
- `top_actors`: `5`
- `variant`: `enriched`
- `outputs`: `cve_apt_paths_enriched.json`
