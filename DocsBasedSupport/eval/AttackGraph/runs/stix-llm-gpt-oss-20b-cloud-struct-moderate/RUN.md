# AttackGraph run: `stix-llm-gpt-oss-20b-cloud-struct-moderate`

This folder collects the outputs of one experiment over the MITRE ATT&CK
knowledge graph. Each section below records a script that was run into
this folder, including parameters and the files it produced. The folder
is self-contained: copy / archive / commit it to keep the experiment
reproducible.


## extract_stix_uses_graph.py
- `timestamp_utc`: `2026-06-03T15:37:29+00:00`
- `bundle_path`: `/Users/bkosinski/Desktop/STUDIA/MGR/SecSearch/DocsBasedSupport/data/ontologies/mitre_attack/enterprise-attack.json`
- `graph_variant`: `llm-extracted:gpt-oss-20b-cloud:struct-moderate`
- `limit`: `null`
- `model`: `gpt-oss:20b-cloud`
- `prior_edges_deleted`: `0`
- `reset`: `true`
- `structure_metrics`: `{'header_line_ratio': 0.0, 'technique_id_per_100_words': 3.2862, 'avg_paragraph_words': 681.5941, 'paragraph_count': 1.0, 'mean_lack_of_structure_score': 0.6491, 'documents': 170}`
- `structure_profile`: `moderate`
- `structure_seed`: `20260603`
- `outputs`: `stix_actor_corpus.json`, `stix_uses_extraction.json`

## eval_stix_extraction_quality.py
- `timestamp_utc`: `2026-06-03T15:37:30+00:00`
- `corpus_path`: `/Users/bkosinski/Desktop/STUDIA/MGR/SecSearch/DocsBasedSupport/eval/AttackGraph/runs/stix-llm-gpt-oss-20b-cloud-struct-moderate/stix_actor_corpus.json`
- `graph_variant`: `llm-extracted:gpt-oss-20b-cloud:struct-moderate`
- `outputs`: `extraction_quality.json`

## eval_link_prediction.py
- `timestamp_utc`: `2026-06-03T15:37:34+00:00`
- `graph_variant`: `llm-extracted:gpt-oss-20b-cloud:struct-moderate`
- `hold_out_fraction`: `0.2`
- `max_actors`: `null`
- `num_candidates`: `697`
- `num_evaluated_actors`: `118`
- `num_held_out_edges`: `528`
- `num_total_edges`: `2644`
- `seed`: `20260529`
- `top_ks`: `5, 10, 20, 50`
- `outputs`: `link_prediction.json`
