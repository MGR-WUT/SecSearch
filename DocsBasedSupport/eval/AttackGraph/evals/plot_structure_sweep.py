"""Plot Experiment A structure-sweep link-prediction metrics as PNG charts.

Uses plotly (same style as CodeGeneration/CodeGuard visualization): plotly_white
template, lines+markers, horizontal legend below the plot. For each ranking strategy
it draws Hits@K (K in 5/10/20/50) with one line per noise profile
(structured -> mild -> moderate -> severe). MRR is plotted separately.

Run from the DocsBasedSupport root:
    PYTHONPATH=. python eval/AttackGraph/evals/plot_structure_sweep.py
"""

from __future__ import annotations

import json
from pathlib import Path

import plotly.graph_objects as go

BASE = Path("eval/AttackGraph/runs")
OUT = Path("eval/AttackGraph/figures")

# Profile label -> run directory (ordered by increasing structure loss).
PROFILES: dict[str, str] = {
    "Structured": "stix-llm-gpt-oss-20b-cloud",
    "Mild": "stix-llm-gpt-oss-20b-cloud-struct-mild",
    "Moderate": "stix-llm-gpt-oss-20b-cloud-struct-moderate",
    "Severe": "stix-llm-gpt-oss-20b-cloud-struct-severe",
}

STRATEGIES: dict[str, str] = {
    "random": "Random",
    "popularity": "Popularity (PageRank only)",
    "neighbour": "Neighbour (graph traversal)",
    "neighbour_pagerank": "Neighbour + PageRank",
}

KS = [5, 10, 20, 50]

# Sequential colour ramp: more structure loss -> warmer colour. Matches the
# blue/red accent palette used in the CodeGuard visualization.
PROFILE_COLOURS = {
    "Structured": "#4C72B0",
    "Mild": "#2CA02C",
    "Moderate": "#DD8452",
    "Severe": "#C41E3A",
}
STRATEGY_COLOURS = {
    "random": "#8C8C8C",
    "popularity": "#4C72B0",
    "neighbour": "#C41E3A",
    "neighbour_pagerank": "#DD8452",
}
PROFILE_SYMBOLS = {
    "Structured": "circle",
    "Mild": "square",
    "Moderate": "triangle-up",
    "Severe": "diamond",
}
STRATEGY_SYMBOLS = {
    "random": "circle",
    "popularity": "square",
    "neighbour": "triangle-up",
    "neighbour_pagerank": "diamond",
}


def load() -> dict[str, dict]:
    data: dict[str, dict] = {}
    for label, run in PROFILES.items():
        path = BASE / run / "link_prediction.json"
        data[label] = json.loads(path.read_text())["aggregated"]
    return data


def _finalize(fig: go.Figure, *, title: str, x_title: str, y_title: str) -> None:
    fig.update_xaxes(title_text=x_title, showgrid=True, automargin=True)
    fig.update_yaxes(title_text=y_title, showgrid=True, automargin=True)
    fig.update_layout(
        title=dict(text=title, x=0.5, xanchor="center", y=0.97),
        template="plotly_white",
        height=480,
        width=620,
        margin=dict(t=70, b=110, l=70, r=30),
        legend=dict(
            orientation="h",
            yanchor="top",
            y=-0.22,
            x=0.5,
            xanchor="center",
            bgcolor="rgba(255,255,255,0.9)",
            bordercolor="#cccccc",
            borderwidth=1,
        ),
    )


def _add_line(
    fig: go.Figure, x: list, y: list, *, name: str, color: str, symbol: str
) -> None:
    fig.add_trace(
        go.Scatter(
            x=x,
            y=y,
            mode="lines+markers",
            name=name,
            line=dict(color=color, width=2),
            marker=dict(symbol=symbol, size=11, color=color, line=dict(width=1, color="white")),
        )
    )


def plot_hits(data: dict[str, dict]) -> None:
    for strat_key, strat_name in STRATEGIES.items():
        fig = go.Figure()
        for label, agg in data.items():
            ys = [100 * agg[strat_key][f"hits@{k}"] for k in KS]
            _add_line(
                fig, KS, ys,
                name=label,
                color=PROFILE_COLOURS[label],
                symbol=PROFILE_SYMBOLS[label],
            )
        fig.update_xaxes(tickmode="array", tickvals=KS)
        fig.update_yaxes(range=[0, 100])
        _finalize(
            fig,
            title=f"Hits@K by noise level - {strat_name}",
            x_title="K (rank cut-off)",
            y_title="Hits@K (%)",
        )
        out = OUT / f"hits_at_k_{strat_key}.png"
        fig.write_image(out, scale=2)
        print(f"wrote {out}")


def plot_mrr(data: dict[str, dict]) -> None:
    labels = list(data.keys())
    fig = go.Figure()
    for strat_key, strat_name in STRATEGIES.items():
        ys = [data[label][strat_key]["mrr"] for label in labels]
        _add_line(
            fig, labels, ys,
            name=strat_name,
            color=STRATEGY_COLOURS[strat_key],
            symbol=STRATEGY_SYMBOLS[strat_key],
        )
    fig.update_yaxes(range=[0, 0.45])
    _finalize(
        fig,
        title="Mean Reciprocal Rank by noise level",
        x_title="Noise level (increasing structure loss)",
        y_title="MRR",
    )
    out = OUT / "mrr_by_noise.png"
    fig.write_image(out, scale=2)
    print(f"wrote {out}")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    data = load()
    plot_hits(data)
    plot_mrr(data)


if __name__ == "__main__":
    main()
