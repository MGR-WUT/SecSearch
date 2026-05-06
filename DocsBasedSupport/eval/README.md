# Evaluation data layout

Store only real benchmark inputs and outputs here, grouped by benchmark name.

Recommended structure:

- `eval/WildGraphBench/*.json`
- `eval/<benchmarkName>/*.json`

Notes:

- Do not commit synthetic/mock datasets.
- Keep generated reports next to the benchmark they belong to.
- Use `eval/run.py --dataset ... --output ...` with paths inside `eval/<benchmarkName>/`.
