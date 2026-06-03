# AttackGraph run: `baseline-clean-compare`

This folder collects the outputs of one experiment over the MITRE ATT&CK
knowledge graph. Each section below records a script that was run into
this folder, including parameters and the files it produced. The folder
is self-contained: copy / archive / commit it to keep the experiment
reproducible.


## eval_link_prediction.py
- `timestamp_utc`: `2026-06-03T13:08:54+00:00`
- `graph_variant`: `null`
- `hold_out_fraction`: `0.2`
- `max_actors`: `null`
- `num_candidates`: `697`
- `num_evaluated_actors`: `111`
- `num_held_out_edges`: `304`
- `num_total_edges`: `1520`
- `seed`: `20260529`
- `top_ks`: `5, 10, 20, 50`
- `outputs`: `link_prediction.json`
