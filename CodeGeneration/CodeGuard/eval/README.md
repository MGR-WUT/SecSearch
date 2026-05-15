# CodeGuard evaluation results

```
eval/
├── instruct/
│   └── results/          # instruct_stat.json, instruct_responses_*.json
├── autocomplete/
│   └── results/          # autocomplete_stat.json, autocomplete_responses_*.json
└── visualization/
    └── codeguard_results_visualization.ipynb
```

## Adding new results

After running CyberSecEval4, save outputs under the matching benchmark folder:

| Benchmark    | Stat file              | Response files                    |
|-------------|------------------------|-----------------------------------|
| instruct    | `instruct/results/instruct_stat.json` | `instruct_responses_<model>.json` |
| autocomplete | `autocomplete/results/autocomplete_stat.json` | `autocomplete_responses_<model>.json` |

## Visualization

```bash
cd eval/visualization
pip install pandas plotly
jupyter notebook codeguard_results_visualization.ipynb
```
