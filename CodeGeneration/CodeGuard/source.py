import yaml
from agents import create_llm, create_generator, create_auditor, create_refiner
from static_analysis import run_bandit, has_issues


class CodeGuard:
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self._setup_agents()

    def _load_config(self, path: str):
        with open(path, "r") as f:
            return yaml.safe_load(f)

    def _setup_agents(self):
        # Generator + Refiner share same model
        gen_model = self.config["llm"]["generator_model"]
        gen_llm = create_llm(gen_model)

        self.generator = create_generator(gen_llm)
        self.refiner = create_refiner(gen_llm)

        # Optional auditor
        if self.config["agents"].get("use_auditor", False):
            audit_model = self.config["llm"]["auditor_model"]
            audit_llm = create_llm(audit_model)
            self.auditor = create_auditor(audit_llm)
        else:
            self.auditor = None

    def _analyze_security(self, code: str):
        bandit_result = run_bandit(code)
        issues_exist = has_issues(bandit_result)
        return issues_exist, bandit_result

    def _build_feedback(self, code: str, bandit_result):
        feedback = str(bandit_result)

        if self.auditor:
            llm_feedback = self.auditor.run(code=code)
            feedback += "\n\nLLM Audit:\n" + llm_feedback

        return feedback

    def run(self, task: str):
        max_iters = self.config["execution"]["max_iterations"]

        # Initial generation
        code = self.generator.run(task=task)

        history = []

        for i in range(max_iters):
            if self.config["logging"]["verbose"]:
                print(f"\n--- Iteration {i+1} ---")

            issues_exist, bandit_result = self._analyze_security(code)

            history.append({"iteration": i + 1, "issues": bandit_result})

            if not issues_exist:
                if self.config["logging"]["verbose"]:
                    print("✅ Security policy satisfied")
                break

            feedback = self._build_feedback(code, bandit_result)
            code = self.refiner.run(code=code, feedback=feedback)

        return {"final_code": code, "iterations": len(history), "history": history}
