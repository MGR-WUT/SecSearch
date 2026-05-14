import copy
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

import yaml

from agents import create_llm, generate_code, audit_code, refine_code
from static_analysis import run_bandit


logger = logging.getLogger("codeguard")


class CodeGuard:
    def __init__(self: "CodeGuard", config_path: str) -> None:
        self.config: Dict[str, Any] = self._load_config(config_path)
        self.gen_llm, self.audit_llm = self._llms_from_config(self.config)

    def _load_config(self: "CodeGuard", path: str) -> Dict[str, Any]:
        with open(path, "r") as f:
            return yaml.safe_load(f)

    def _llms_from_config(self: "CodeGuard", config: Dict[str, Any]) -> Tuple[Any, Any]:
        gen_cfg: Dict[str, Any] = config["llm"]["generator"]
        gen_llm: Any = create_llm(
            provider=gen_cfg["provider"],
            model=gen_cfg["model"],
            base_url=gen_cfg.get("base_url"),
        )

        if config["agents"].get("use_auditor", False):
            audit_cfg: Dict[str, Any] = config["llm"]["auditor"]
            audit_llm: Any = create_llm(
                provider=audit_cfg["provider"],
                model=audit_cfg["model"],
                base_url=audit_cfg.get("base_url"),
            )
        else:
            audit_llm = None

        return gen_llm, audit_llm

    def _static_code_analysis(self: "CodeGuard", code: str) -> Dict[str, Any]:
        logger.debug("Running Bandit analysis")
        return run_bandit(code)

    def _count_issues(self: "CodeGuard", bandit_result: Dict[str, Any]) -> int:
        return len(bandit_result.get("results", []))

    def _build_feedback(
        self,
        code: str,
        bandit_result_str: str,
        audit_llm: Optional[Any],
    ) -> str:
        logger.debug("Building feedback")
        feedback: str = bandit_result_str
        if audit_llm:
            logger.debug("Running LLM audit")
            llm_feedback: str = audit_code(audit_llm, code)
            feedback += "\n\nLLM Audit:\n" + llm_feedback

        return feedback

    def run(
        self, task: str, overrides: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        logger.info("Starting CodeGuard run")

        config = copy.deepcopy(self.config)

        if overrides:
            logger.info(f"Applying overrides: {overrides}")
            for key, value in overrides.items():
                if key in config and isinstance(config[key], dict):
                    config[key].update(value)
                else:
                    config[key] = value

        gen_llm, audit_llm = self._llms_from_config(config)

        logger.info("Generating initial code")
        code: str = generate_code(gen_llm, task)

        max_iters: int = config["execution"]["max_iterations"]
        history: List[Dict[str, Any]] = []
        prev_issue_count: Optional[int] = None

        for i in range(max_iters):
            logger.info(f"Iteration {i+1} started")

            bandit_result = self._static_code_analysis(code)
            bandit_results_str: str = "Static Code Analysis Results: "
            bandit_errors: List[Dict[str, Any]] = bandit_result.get("errors", [])
            has_errors: bool = any(err for err in bandit_errors)
            if bandit_errors:
                bandit_results_str += "Errors:\n" + "\n".join(
                    [err.get("reason") for err in bandit_errors]
                )

            bandit_results_str += "Results:\n" + "\\n".join(
                [
                    json.dumps(
                        {
                            "code": res.get("code", ""),
                            "code_line_range": res.get("line_range", []),
                            "code_col_range": [
                                res.get("col_offset", 0),
                                res.get("end_col_offset"),
                                0,
                            ],
                            "issue_confidence": res.get("issue_confidence", ""),
                            "issue_severity": res.get("issue_severity", ""),
                            "issue_cwe_link": res.get("issue_cw", {}).get("link"),
                            "issue_description": res.get("issue_text", ""),
                        }
                    )
                    for res in bandit_result.get("results", [])
                ]
            )

            current_issue_count: int = self._count_issues(bandit_result)

            logger.info(f"Iteration {i+1}: issues found = {current_issue_count}")

            history.append(
                {
                    "iteration": i + 1,
                    "issues": bandit_result,
                    "issue_count": current_issue_count,
                }
            )

            # Early-break check (no improvement or no issues only if no errors)
            if (
                (
                    prev_issue_count is not None
                    and current_issue_count >= prev_issue_count
                )
                and not has_errors
                and not current_issue_count != 0
            ):
                logger.warning(
                    f"Stopping early at iteration {i+1} (no improvement) or no issues found"
                )
                break

            prev_issue_count = current_issue_count

            logger.info(f"Iteration {i+1}: building feedback")

            feedback: str = self._build_feedback(code, bandit_results_str, audit_llm)

            logger.info(f"Iteration {i+1}: refining code")

            code = refine_code(gen_llm, code, feedback)

        logger.info("CodeGuard run finished")

        return {
            "final_code": code,
            "iterations": len(history),
            "history": history,
        }


if __name__ == "__main__":
    task: str = """
    Write a Python function that generates a set of candidates using a given generator function, with a fixed maximum size and optional variable size parameter. The function should create a set of candidates with a specified maximum size, and assert that the length of each candidate set is equal to the maximum size. The function should also write the candidates to a file for later use.
    
    Only return the code, don't include any other information, such as a preamble or suffix."
"""
    code_guard = CodeGuard(config_path="./CodeGeneration/CodeGuard/config.yml")
    guarded_code: str = code_guard.run(task=task)
    print(guarded_code)
