# AttackGraph run: `kev-gpt-oss-20b-cloud`

This folder collects the outputs of one experiment over the MITRE ATT&CK
knowledge graph. Each section below records a script that was run into
this folder, including parameters and the files it produced. The folder
is self-contained: copy / archive / commit it to keep the experiment
reproducible.


## load_attack.py
- `timestamp_utc`: `2026-06-03T15:06:02+00:00`
- `bundle_path`: `/Users/bkosinski/Desktop/STUDIA/MGR/SecSearch/DocsBasedSupport/data/ontologies/mitre_attack/enterprise-attack.json`
- `bundle_url`: `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
- `enrich`: `true`
- `reset`: `true`
- `source_id`: `mitre-attack:enterprise`
- `outputs`: `load_summary.json`

## load_kev.py
- `timestamp_utc`: `2026-06-03T15:07:02+00:00`
- `kev_url`: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- `num_cves_loaded`: `1610`
- `reset`: `true`
- `sample`: `null`
- `seed`: `20260603`
- `outputs`: `kev_load_summary.json`

## eval_cve_apt.py
- `timestamp_utc`: `2026-06-03T15:08:39+00:00`
- `coverage_fraction`: `0.0106`
- `cve_source`: `cisa-kev`
- `ingestion_model`: `(none)`
- `max_hops`: `3`
- `max_paths_per_pair`: `10`
- `num_cves`: `1610`
- `num_cves_with_actor_link`: `17`
- `pagerank_property`: `pagerank`
- `top_actors`: `5`
- `variant`: `baseline`
- `outputs`: `cve_apt_paths_baseline.json`

## enrich_with_llm.py
- `timestamp_utc`: `2026-06-03T16:11:08+00:00`
- `cve_source`: `cisa-kev`
- `dropped_unmatched_actors`: `46`
- `dropped_unmatched_malware`: `83`
- `dropped_unquoted`: `0`
- `force`: `false`
- `ingestion_model`: `gpt-oss-20b-cloud`
- `labels`: `CVE`
- `limit`: `null`
- `model`: `gpt-oss:20b-cloud`
- `new_actor_exploit_edges`: `0`
- `new_attribution_edges`: `0`
- `new_cve_nodes`: `0`
- `new_exploits_edges`: `0`
- `new_malware_exploit_edges`: `1`
- `parse_failures`: `96`
- `processed_entities`: `1610`
- `provider`: `ollama`
- `source_id`: `mitre-attack:enterprise`
- `outputs`: `llm_enrichment.json`

## load_attack.py
- `timestamp_utc`: `2026-06-03T16:16:26+00:00`
- `bundle_path`: `/Users/bkosinski/Desktop/STUDIA/MGR/SecSearch/DocsBasedSupport/data/ontologies/mitre_attack/enterprise-attack.json`
- `bundle_url`: `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
- `enrich`: `true`
- `reset`: `false`
- `source_id`: `mitre-attack:enterprise`
- `outputs`: `load_summary.json`

## eval_cve_apt.py
- `timestamp_utc`: `2026-06-03T16:16:31+00:00`
- `coverage_fraction`: `0.0006`
- `cve_source`: `cisa-kev`
- `ingestion_model`: `gpt-oss-20b-cloud`
- `max_hops`: `3`
- `max_paths_per_pair`: `10`
- `num_cves`: `1585`
- `num_cves_with_actor_link`: `1`
- `pagerank_property`: `pagerank`
- `top_actors`: `5`
- `variant`: `enriched`
- `outputs`: `cve_apt_paths_enriched.json`

## cve_scaling_report.py
- `timestamp_utc`: `2026-06-03T16:16:34+00:00`
- `baseline_report`: `eval/AttackGraph/runs/kev-gpt-oss-20b-cloud/cve_apt_paths_baseline.json`
- `bootstrap_iters`: `200`
- `enriched_report`: `eval/AttackGraph/runs/kev-gpt-oss-20b-cloud/cve_apt_paths_enriched.json`
- `sample_sizes`: `33, 100, 200, 400, 800`
- `seed`: `20260603`
- `outputs`: `cve_scaling_report.json`, `cve_attribution_sample.csv`

## eval_cve_apt.py
- `timestamp_utc`: `2026-06-03T16:19:47+00:00`
- `coverage_fraction`: `0.0006`
- `cve_source`: `cisa-kev`
- `ingestion_model`: `(none)`
- `max_hops`: `3`
- `max_paths_per_pair`: `10`
- `num_cves`: `1585`
- `num_cves_with_actor_link`: `1`
- `pagerank_property`: `pagerank`
- `top_actors`: `5`
- `variant`: `baseline`
- `outputs`: `cve_apt_paths_baseline.json`

## cve_scaling_report.py
- `timestamp_utc`: `2026-06-03T16:19:58+00:00`
- `baseline_report`: `eval/AttackGraph/runs/kev-gpt-oss-20b-cloud/cve_apt_paths_baseline.json`
- `bootstrap_iters`: `200`
- `enriched_report`: `eval/AttackGraph/runs/kev-gpt-oss-20b-cloud/cve_apt_paths_enriched.json`
- `sample_sizes`: `33, 100, 200, 400, 800`
- `seed`: `20260603`
- `outputs`: `cve_scaling_report.json`, `cve_attribution_sample.csv`
