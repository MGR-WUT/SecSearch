from __future__ import annotations

import argparse
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from typing import Any

import httpx
import yaml

from app.core.config import Settings, get_settings
from app.graph.neo4j_store import Neo4jStore
from app.pipeline.extraction import ExtractionService
from app.pipeline.ingestion import IngestedDocument
from app.pipeline.query_agent_v2 import GraphRAGV2Service

logger = logging.getLogger("wildgraphbench-runner")


@dataclass
class WildGraphQuestion:
    qid: Any
    question: str
    answer: str
    gold_statements: list[str]
    question_type: list[str]
    raw: dict[str, Any]


def _load_questions(question_file: Path, max_questions: int | None = None) -> list[WildGraphQuestion]:
    questions: list[WildGraphQuestion] = []
    with question_file.open("r", encoding="utf-8") as fh:
        for line in fh:
            payload = (line or "").strip()
            if not payload:
                continue
            row = json.loads(payload)
            qid = row.get("id")
            question = (row.get("question") or "").strip()
            answer = (row.get("answer") or "").strip()
            gold_statements_raw = row.get("gold_statements") or []
            if isinstance(gold_statements_raw, list):
                gold_statements = [str(item).strip() for item in gold_statements_raw if str(item).strip()]
            else:
                gold_statements = []
            if not answer and gold_statements:
                answer = " ".join(gold_statements)
            qtype = row.get("question_type") or []
            if isinstance(qtype, str):
                qtype = [qtype]
            if not question:
                continue
            questions.append(
                WildGraphQuestion(
                    qid=qid,
                    question=question,
                    answer=answer,
                    gold_statements=gold_statements,
                    question_type=[str(item) for item in qtype],
                    raw=row,
                )
            )
            if max_questions is not None and len(questions) >= max_questions:
                break
    return questions


def _collect_reference_pages(corpus_dir: Path, domain: str | None) -> list[Path]:
    if domain:
        candidate_root = corpus_dir / domain
        if not candidate_root.exists():
            raise ValueError(f"Domain '{domain}' not found under corpus path: {corpus_dir}")
        topic_dirs = [path for path in sorted(candidate_root.iterdir()) if path.is_dir()]
    else:
        topic_dirs = []
        for domain_dir in sorted(corpus_dir.iterdir()):
            if not domain_dir.is_dir():
                continue
            topic_dirs.extend(path for path in sorted(domain_dir.iterdir()) if path.is_dir())

    pages: list[Path] = []
    for topic_dir in topic_dirs:
        ref_dir = topic_dir / "reference_pages"
        if not ref_dir.exists():
            continue
        pages.extend(sorted(ref_dir.glob("*.txt")))
    return pages


def _build_source_id(domain: str, topic: str, page_path: Path) -> str:
    stem = page_path.stem.replace(" ", "_")
    return f"wgb:{domain}:{topic}:{stem}"


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m {secs:.1f}s"
    hours, mins = divmod(minutes, 60)
    return f"{int(hours)}h {int(mins)}m {secs:.1f}s"


def _render_progress_line(
    phase: str,
    done: int,
    total: int,
    elapsed_seconds: float,
    eta_seconds: float,
    suffix: str,
) -> str:
    width = 28
    ratio = (done / total) if total else 1.0
    filled = min(width, max(0, int(ratio * width)))
    bar = "#" * filled + "-" * (width - filled)
    percent = ratio * 100
    return (
        f"\r{phase} [{bar}] {done}/{total} ({percent:5.1f}%) "
        f"left={max(total - done, 0)} elapsed={_format_duration(elapsed_seconds)} "
        f"eta={_format_duration(eta_seconds)} {suffix}"
    )


def _ingest_reference_pages(
    pages: list[Path],
    extraction_service: ExtractionService,
    query_agent: GraphRAGV2Service,
    log_every: int,
    show_progress_bar: bool,
) -> dict[str, Any]:
    start = time.perf_counter()
    ingested = 0
    failed = 0
    extracted_entities = 0
    extracted_relations = 0
    indexed_chunks = 0
    failures: list[dict[str, str]] = []

    total = len(pages)
    logger.info("INGEST phase started: %d reference pages", total)

    for idx, page in enumerate(pages, start=1):
        try:
            topic = page.parent.parent.name
            domain = page.parent.parent.parent.name
            text = page.read_text(encoding="utf-8")
            source_id = _build_source_id(domain=domain, topic=topic, page_path=page)
            doc = IngestedDocument(
                source_id=source_id,
                source_uri=str(page),
                source_type="wildgraphbench_reference_txt",
                content=text,
                last_updated=None,
                etag=None,
                content_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            )
            extraction = extraction_service.extract_and_store(doc)
            chunk_count = query_agent.index_document_chunks(doc)
            ingested += 1
            extracted_entities += int(extraction.get("entity_count", 0))
            extracted_relations += int(extraction.get("relation_count", 0))
            indexed_chunks += chunk_count
        except Exception as exc:  # noqa: BLE001 - benchmark loop should continue on single-document failures
            failed += 1
            failures.append({"path": str(page), "error": str(exc)})
            logger.exception("INGEST failed (%d/%d): %s", idx, total, page)

        if idx % log_every == 0 or idx == total:
            elapsed = time.perf_counter() - start
            rate = idx / elapsed if elapsed else 0.0
            eta_seconds = (total - idx) / rate if rate else 0.0
            if show_progress_bar:
                print(
                    _render_progress_line(
                        phase="INGEST",
                        done=idx,
                        total=total,
                        elapsed_seconds=elapsed,
                        eta_seconds=eta_seconds,
                        suffix=f"ok={ingested} failed={failed} chunks={indexed_chunks}",
                    ),
                    end="",
                    flush=True,
                )
            if not show_progress_bar:
                if not show_progress_bar:
                    logger.info(
                        "INGEST progress %d/%d (%.1f%%) | left=%d | ok=%d failed=%d | entities=%d relations=%d chunks=%d | elapsed=%s eta=%s",
                        idx,
                        total,
                        (idx / total * 100) if total else 100.0,
                        max(total - idx, 0),
                        ingested,
                        failed,
                        extracted_entities,
                        extracted_relations,
                        indexed_chunks,
                        _format_duration(elapsed),
                        _format_duration(eta_seconds),
                    )
    if show_progress_bar and total:
        print()

    return {
        "ingested_pages": ingested,
        "failed_pages": failed,
        "entity_count_total": extracted_entities,
        "relation_count_total": extracted_relations,
        "indexed_chunks_total": indexed_chunks,
        "ingest_time_seconds": time.perf_counter() - start,
        "ingest_failures": failures[:50],
    }


def _evaluate_questions(
    query_agent: GraphRAGV2Service,
    questions: list[WildGraphQuestion],
    log_every: int,
    show_progress_bar: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    predictions: list[dict[str, Any]] = []
    latencies: list[float] = []
    evidence_counts: list[int] = []
    non_empty_answers = 0

    total = len(questions)
    phase_start = time.perf_counter()
    logger.info("QA phase started: %d questions", total)

    for idx, q in enumerate(questions, start=1):
        start = time.perf_counter()
        is_summary = any(item.lower() == "summary" for item in q.question_type)
        result = query_agent.answer(
            q.question,
            benchmark_strict=False,
            benchmark_summary=is_summary,
        )
        elapsed = time.perf_counter() - start
        latencies.append(elapsed)
        evidence_counts.append(len(result.evidence_path))
        if result.answer.strip():
            non_empty_answers += 1

        predictions.append(
            {
                "id": q.qid,
                "question": q.question,
                "question_type": q.question_type,
                "gold_answer": q.answer,
                "gold_statements": q.gold_statements,
                "pred_answer": result.answer,
                "answer": result.answer,
                "evidence_path": [edge.model_dump() for edge in result.evidence_path],
                "citations": [citation.model_dump() for citation in result.citations],
            }
        )

        if idx % log_every == 0 or idx == total:
            avg_latency = mean(latencies) if latencies else 0.0
            phase_elapsed = time.perf_counter() - phase_start
            throughput = idx / phase_elapsed if phase_elapsed else 0.0
            eta_seconds = (total - idx) / throughput if throughput else 0.0
            if show_progress_bar:
                print(
                    _render_progress_line(
                        phase="QA",
                        done=idx,
                        total=total,
                        elapsed_seconds=phase_elapsed,
                        eta_seconds=eta_seconds,
                        suffix=f"last={elapsed:.2f}s avg={avg_latency:.2f}s",
                    ),
                    end="",
                    flush=True,
                )
            if not show_progress_bar:
                if not show_progress_bar:
                    logger.info(
                        "QA progress %d/%d (%.1f%%) | left=%d | qid=%s | question=%s | last=%.2fs avg=%.2fs | avg_edges=%.2f | non_empty=%.1f%% | eta=%s",
                        idx,
                        total,
                        (idx / total * 100) if total else 100.0,
                        max(total - idx, 0),
                        str(q.qid),
                        q.question[:90].replace("\n", " "),
                        elapsed,
                        avg_latency,
                        mean(evidence_counts) if evidence_counts else 0.0,
                        ((non_empty_answers / idx) * 100) if idx else 0.0,
                        _format_duration(eta_seconds),
                    )
    if show_progress_bar and total:
        print()

    stats = {
        "questions_count": len(questions),
        "avg_latency_seconds": mean(latencies) if latencies else 0.0,
        "avg_evidence_edges": mean(evidence_counts) if evidence_counts else 0.0,
        "answer_non_empty_rate": (non_empty_answers / len(questions)) if questions else 0.0,
    }
    return predictions, stats


def _ingest_reference_pages_via_api(
    pages: list[Path],
    api_base_url: str,
    request_timeout_seconds: int,
    log_every: int,
    show_progress_bar: bool,
) -> dict[str, Any]:
    max_retries = 3
    backoff_seconds = 1.5
    start = time.perf_counter()
    ingested = 0
    failed = 0
    extracted_entities = 0
    extracted_relations = 0
    indexed_chunks = 0
    failures: list[dict[str, str]] = []

    total = len(pages)
    logger.info("INGEST phase started (API mode): %d reference pages", total)
    with httpx.Client(base_url=api_base_url, timeout=request_timeout_seconds) as client:
        for idx, page in enumerate(pages, start=1):
            try:
                last_exc: Exception | None = None
                for attempt in range(1, max_retries + 2):
                    try:
                        response = client.post("/ingest", json={"pdf_paths": [], "urls": [], "text_paths": [str(page)]})
                        response.raise_for_status()
                        payload = response.json()
                        details = payload.get("details", [])
                        ingested += int(payload.get("ingested", 0))
                        extracted_entities += sum(int(item.get("entity_count", 0)) for item in details)
                        extracted_relations += sum(int(item.get("relation_count", 0)) for item in details)
                        indexed_chunks += sum(int(item.get("v2_chunks_indexed", 0)) for item in details)
                        break
                    except httpx.HTTPStatusError as exc:
                        retryable = exc.response.status_code >= 500
                        last_exc = exc
                        if not retryable or attempt > max_retries:
                            raise
                    except httpx.RequestError as exc:
                        last_exc = exc
                        if attempt > max_retries:
                            raise

                    sleep_seconds = backoff_seconds * (2 ** (attempt - 1))
                    logger.warning(
                        "INGEST retry %d/%d for %s after error: %s",
                        attempt,
                        max_retries,
                        page,
                        last_exc,
                    )
                    time.sleep(sleep_seconds)
            except Exception as exc:  # noqa: BLE001
                failed += 1
                failures.append({"path": str(page), "error": str(exc)})
                logger.exception("INGEST failed (%d/%d): %s", idx, total, page)

            if idx % log_every == 0 or idx == total:
                elapsed = time.perf_counter() - start
                rate = idx / elapsed if elapsed else 0.0
                eta_seconds = (total - idx) / rate if rate else 0.0
                if show_progress_bar:
                    print(
                        _render_progress_line(
                            phase="INGEST",
                            done=idx,
                            total=total,
                            elapsed_seconds=elapsed,
                            eta_seconds=eta_seconds,
                            suffix=f"ok={ingested} failed={failed} chunks={indexed_chunks}",
                        ),
                        end="",
                        flush=True,
                    )
                logger.info(
                    "INGEST progress %d/%d (%.1f%%) | left=%d | ok=%d failed=%d | entities=%d relations=%d chunks=%d | elapsed=%s eta=%s",
                    idx,
                    total,
                    (idx / total * 100) if total else 100.0,
                    max(total - idx, 0),
                    ingested,
                    failed,
                    extracted_entities,
                    extracted_relations,
                    indexed_chunks,
                    _format_duration(elapsed),
                    _format_duration(eta_seconds),
                )
    if show_progress_bar and total:
        print()

    return {
        "ingested_pages": ingested,
        "failed_pages": failed,
        "entity_count_total": extracted_entities,
        "relation_count_total": extracted_relations,
        "indexed_chunks_total": indexed_chunks,
        "ingest_time_seconds": time.perf_counter() - start,
        "ingest_failures": failures[:50],
    }


def _evaluate_questions_via_api(
    questions: list[WildGraphQuestion],
    api_base_url: str,
    request_timeout_seconds: int,
    log_every: int,
    show_progress_bar: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    predictions: list[dict[str, Any]] = []
    latencies: list[float] = []
    evidence_counts: list[int] = []
    non_empty_answers = 0

    total = len(questions)
    phase_start = time.perf_counter()
    logger.info("QA phase started (API mode): %d questions", total)
    with httpx.Client(base_url=api_base_url, timeout=request_timeout_seconds) as client:
        for idx, q in enumerate(questions, start=1):
            start = time.perf_counter()
            is_summary = any(item.lower() == "summary" for item in q.question_type)
            response = client.post(
                "/query_v2",
                json={
                    "question": q.question,
                    "benchmark_strict": False,
                    "benchmark_summary": is_summary,
                },
            )
            response.raise_for_status()
            result = response.json()
            elapsed = time.perf_counter() - start
            latencies.append(elapsed)
            evidence_path = result.get("evidence_path", [])
            citations = result.get("citations", [])
            answer = str(result.get("answer", ""))
            evidence_counts.append(len(evidence_path))
            if answer.strip():
                non_empty_answers += 1

            predictions.append(
                {
                    "id": q.qid,
                    "question": q.question,
                    "question_type": q.question_type,
                    "gold_answer": q.answer,
                    "gold_statements": q.gold_statements,
                    "pred_answer": answer,
                    "answer": answer,
                    "evidence_path": evidence_path,
                    "citations": citations,
                }
            )

            if idx % log_every == 0 or idx == total:
                avg_latency = mean(latencies) if latencies else 0.0
                phase_elapsed = time.perf_counter() - phase_start
                throughput = idx / phase_elapsed if phase_elapsed else 0.0
                eta_seconds = (total - idx) / throughput if throughput else 0.0
                if show_progress_bar:
                    print(
                        _render_progress_line(
                            phase="QA",
                            done=idx,
                            total=total,
                            elapsed_seconds=phase_elapsed,
                            eta_seconds=eta_seconds,
                            suffix=f"last={elapsed:.2f}s avg={avg_latency:.2f}s",
                        ),
                        end="",
                        flush=True,
                    )
                logger.info(
                    "QA progress %d/%d (%.1f%%) | left=%d | qid=%s | question=%s | last=%.2fs avg=%.2fs | avg_edges=%.2f | non_empty=%.1f%% | eta=%s",
                    idx,
                    total,
                    (idx / total * 100) if total else 100.0,
                    max(total - idx, 0),
                    str(q.qid),
                    q.question[:90].replace("\n", " "),
                    elapsed,
                    avg_latency,
                    mean(evidence_counts) if evidence_counts else 0.0,
                    ((non_empty_answers / idx) * 100) if idx else 0.0,
                    _format_duration(eta_seconds),
                )
    if show_progress_bar and total:
        print()

    stats = {
        "questions_count": len(questions),
        "avg_latency_seconds": mean(latencies) if latencies else 0.0,
        "avg_evidence_edges": mean(evidence_counts) if evidence_counts else 0.0,
        "answer_non_empty_rate": (non_empty_answers / len(questions)) if questions else 0.0,
    }
    return predictions, stats


def _question_matches_types(question: WildGraphQuestion, question_types: set[str] | None) -> bool:
    if not question_types:
        return True
    normalized = {item.lower() for item in question.question_type}
    return bool(normalized & question_types)


def _filter_questions(
    questions: list[WildGraphQuestion],
    question_types: set[str] | None,
) -> list[WildGraphQuestion]:
    if not question_types:
        return questions
    return [q for q in questions if _question_matches_types(q, question_types)]


def _load_predictions_jsonl(path: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    by_question: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            payload = (line or "").strip()
            if not payload:
                continue
            row = json.loads(payload)
            question = (row.get("question") or "").strip()
            if question:
                by_question[question] = row
                order.append(question)
    return by_question, order


def _merge_predictions(
    base_predictions: dict[str, dict[str, Any]],
    updated_rows: list[dict[str, Any]],
    base_order: list[str] | None = None,
) -> list[dict[str, Any]]:
    merged = dict(base_predictions)
    for row in updated_rows:
        question = (row.get("question") or "").strip()
        if question:
            merged[question] = row
    if base_order:
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for question in base_order:
            if question in merged:
                rows.append(merged[question])
                seen.add(question)
        for question, row in merged.items():
            if question not in seen:
                rows.append(row)
        return rows
    return list(merged.values())


def _load_domain_questions(wgb_root: Path, domain: str | None, max_questions: int | None) -> list[WildGraphQuestion]:
    qa_root = wgb_root / "QA"
    if not qa_root.exists():
        raise ValueError(f"Missing QA directory in benchmark root: {qa_root}")

    if domain:
        domain_files = [qa_root / domain / "questions.jsonl"]
    else:
        domain_files = sorted(qa_root.glob("*/questions.jsonl"))

    all_questions: list[WildGraphQuestion] = []
    for qfile in domain_files:
        if not qfile.exists():
            continue
        all_questions.extend(_load_questions(qfile))
        if max_questions is not None and len(all_questions) >= max_questions:
            return all_questions[:max_questions]
    return all_questions


def _parse_optional_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise ValueError(f"Invalid boolean value: {value}")


def _load_settings_from_cli(args: argparse.Namespace) -> Settings:
    base = get_settings().model_dump()

    if args.settings_yaml:
        settings_path = Path(args.settings_yaml).resolve()
        if not settings_path.exists():
            raise ValueError(f"Settings YAML not found: {settings_path}")
        with settings_path.open("r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        if not isinstance(loaded, dict):
            raise ValueError("Provided settings YAML must contain a top-level mapping.")
        base.update(loaded)

    cli_overrides: dict[str, Any] = {}
    for field in (
        "app_name",
        "app_env",
        "llm_provider",
        "llm_base_url",
        "llm_api_key",
        "llm_chat_model",
        "llm_extract_model",
        "llm_embed_model",
        "neo4j_uri",
        "neo4j_username",
        "neo4j_password",
        "neo4j_database",
        "graphrag_v2_index_name",
        "graphrag_v2_top_k",
        "graphrag_v2_embedding_dims",
    ):
        value = getattr(args, field, None)
        if value is not None:
            cli_overrides[field] = value

    allow_remote = _parse_optional_bool(args.app_allow_remote_providers)
    if allow_remote is not None:
        cli_overrides["app_allow_remote_providers"] = allow_remote

    base.update(cli_overrides)
    settings = Settings(**base)
    settings.validate_required()
    settings.validate_local_only()
    return settings


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    parser = argparse.ArgumentParser(description="Run end-to-end WildGraphBench evaluation for this GraphRAG pipeline.")
    parser.add_argument("--wildgraphbench-root", required=True, help="Path to local WildGraphBench dataset root.")
    parser.add_argument("--domain", help="Optional domain name (e.g. technology). If omitted, evaluates all domains.")
    parser.add_argument(
        "--output-dir",
        default="eval/WildGraphBench",
        help="Directory for generated predictions and report files.",
    )
    parser.add_argument(
        "--max-reference-pages",
        type=int,
        help="Optional cap on ingested reference pages (useful for smoke tests).",
    )
    parser.add_argument("--max-questions", type=int, help="Optional cap on total evaluated questions.")
    parser.add_argument(
        "--skip-ingest",
        action="store_true",
        help="Skip graph build and only run question answering against the existing graph.",
    )
    parser.add_argument(
        "--ingest-log-every",
        type=int,
        default=10,
        help="Log ingest progress every N reference pages.",
    )
    parser.add_argument(
        "--qa-log-every",
        type=int,
        default=1,
        help="Log QA progress every N questions.",
    )
    parser.add_argument(
        "--mode",
        choices=("local", "api"),
        default="local",
        help="Execution mode: 'local' runs GraphRAG in-process (default); 'api' calls DocsBasedSupport HTTP endpoints.",
    )
    parser.add_argument(
        "--api-base-url",
        default="http://localhost:8008",
        help="DocsBasedSupport API base URL (not CodeGuard on :8000). Start with: python -m app.main",
    )
    parser.add_argument(
        "--request-timeout-seconds",
        type=int,
        default=120,
        help="HTTP timeout in seconds for API mode requests.",
    )
    parser.add_argument(
        "--verbose-http",
        action="store_true",
        help="Enable verbose HTTP client logs (disabled by default).",
    )
    parser.add_argument(
        "--no-progress-bar",
        action="store_true",
        help="Disable in-place progress bar output.",
    )
    parser.add_argument(
        "--question-types",
        help="Comma-separated question types to run (e.g. summary). Others are skipped unless --merge-predictions is set.",
    )
    parser.add_argument(
        "--merge-predictions",
        help="Path to an existing predictions JSONL; non-run questions are copied from this file.",
    )
    parser.add_argument(
        "--settings-yaml",
        help="Optional path to YAML settings file used for this run (merged over default settings).",
    )
    parser.add_argument("--app-name")
    parser.add_argument("--app-env")
    parser.add_argument(
        "--app-allow-remote-providers",
        help="Optional bool override: true/false.",
    )
    parser.add_argument("--llm-provider")
    parser.add_argument("--llm-base-url")
    parser.add_argument("--llm-api-key")
    parser.add_argument("--llm-chat-model")
    parser.add_argument("--llm-extract-model")
    parser.add_argument("--llm-embed-model")
    parser.add_argument("--neo4j-uri")
    parser.add_argument("--neo4j-username")
    parser.add_argument("--neo4j-password")
    parser.add_argument("--neo4j-database")
    parser.add_argument("--graphrag-v2-index-name")
    parser.add_argument("--graphrag-v2-top-k", type=int)
    parser.add_argument("--graphrag-v2-embedding-dims", type=int)
    args = parser.parse_args()
    if not args.verbose_http:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
    show_progress_bar = not args.no_progress_bar

    wgb_root = Path(args.wildgraphbench_root).resolve()
    corpus_root = wgb_root / "corpus"
    if not corpus_root.exists():
        raise ValueError(f"Missing corpus directory in benchmark root: {corpus_root}")

    settings = _load_settings_from_cli(args)
    pages: list[Path] = []
    if not args.skip_ingest:
        pages = _collect_reference_pages(corpus_root, args.domain)
        if args.max_reference_pages is not None:
            pages = pages[: args.max_reference_pages]
    all_questions = _load_domain_questions(wgb_root, args.domain, args.max_questions)
    question_types_filter: set[str] | None = None
    if args.question_types:
        question_types_filter = {item.strip().lower() for item in args.question_types.split(",") if item.strip()}
    questions = _filter_questions(all_questions, question_types_filter)
    base_predictions: dict[str, dict[str, Any]] = {}
    base_prediction_order: list[str] = []
    if args.merge_predictions:
        merge_path = Path(args.merge_predictions).resolve()
        if not merge_path.exists():
            raise ValueError(f"Merge predictions file not found: {merge_path}")
        base_predictions, base_prediction_order = _load_predictions_jsonl(merge_path)
    logger.info(
        "Setup summary | mode=%s | domain=%s | skip_ingest=%s | reference_pages=%d | questions=%d/%d | types=%s | provider=%s | extract_model=%s | chat_model=%s | embed_model=%s | neo4j_db=%s | api_base_url=%s",
        args.mode,
        args.domain or "all",
        bool(args.skip_ingest),
        len(pages),
        len(questions),
        len(all_questions),
        ",".join(sorted(question_types_filter)) if question_types_filter else "all",
        settings.llm_provider,
        settings.llm_extract_model,
        settings.llm_chat_model,
        settings.llm_embed_model,
        settings.neo4j_database,
        args.api_base_url,
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    ingest_stats: dict[str, Any] = {}
    if args.mode == "api":
        if not args.skip_ingest:
            ingest_stats = _ingest_reference_pages_via_api(
                pages=pages,
                api_base_url=args.api_base_url,
                request_timeout_seconds=args.request_timeout_seconds,
                log_every=max(1, args.ingest_log_every),
                show_progress_bar=show_progress_bar,
            )
        predictions, qa_stats = _evaluate_questions_via_api(
            questions=questions,
            api_base_url=args.api_base_url,
            request_timeout_seconds=args.request_timeout_seconds,
            log_every=max(1, args.qa_log_every),
            show_progress_bar=show_progress_bar,
        )
    else:
        store = Neo4jStore(
            uri=settings.neo4j_uri,
            username=settings.neo4j_username,
            password=settings.neo4j_password,
            database=settings.neo4j_database,
        )
        try:
            store.ensure_schema()
            extraction = ExtractionService(
                graph_store=store,
                llm_provider=settings.llm_provider,
                llm_base_url=settings.llm_base_url,
                llm_api_key=settings.llm_api_key,
                model=settings.llm_extract_model,
            )
            query_agent = GraphRAGV2Service(
                graph_store=store,
                llm_provider=settings.llm_provider,
                llm_base_url=settings.llm_base_url,
                llm_api_key=settings.llm_api_key,
                embed_model=settings.llm_embed_model,
                chat_model=settings.llm_chat_model,
                index_name=settings.graphrag_v2_index_name,
                embedding_dims=settings.graphrag_v2_embedding_dims,
                top_k=settings.graphrag_v2_top_k,
            )
            if not args.skip_ingest:
                ingest_stats = _ingest_reference_pages(
                    pages=pages,
                    extraction_service=extraction,
                    query_agent=query_agent,
                    log_every=max(1, args.ingest_log_every),
                    show_progress_bar=show_progress_bar,
                )
            predictions, qa_stats = _evaluate_questions(
                query_agent=query_agent,
                questions=questions,
                log_every=max(1, args.qa_log_every),
                show_progress_bar=show_progress_bar,
            )
        finally:
            store.close()

    stem = args.domain or "all_domains"
    pred_path = output_dir / f"predictions_{stem}.jsonl"
    output_rows = predictions
    if base_predictions:
        output_rows = _merge_predictions(
            base_predictions,
            predictions,
            base_order=base_prediction_order,
        )
    with pred_path.open("w", encoding="utf-8") as fh:
        for row in output_rows:
            fh.write(json.dumps(row, ensure_ascii=True) + "\n")

    report = {
        "benchmark": "WildGraphBench",
        "mode": args.mode,
        "api_base_url": args.api_base_url if args.mode == "api" else None,
        "domain": args.domain or "all",
        "wildgraphbench_root": str(wgb_root),
        "skip_ingest": bool(args.skip_ingest),
        "question_types_filter": sorted(question_types_filter) if question_types_filter else None,
        "merge_predictions": str(Path(args.merge_predictions).resolve()) if args.merge_predictions else None,
        "ingestion": ingest_stats,
        "qa": qa_stats,
        "artifacts": {"predictions_jsonl": str(pred_path)},
    }
    report_path = output_dir / f"report_{stem}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Predictions written to: {pred_path}")
    print(f"Report written to: {report_path}")


if __name__ == "__main__":
    main()
