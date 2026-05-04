## Code Generation Task Implementation Overview

In the [CodeGuard](./CodeGuard/) directory there is a full implementation of the Code Generation Task related to the use of LLMs in SOC environments.

[PurpleLlama](./PurpleLlama/) contains a fork of the [official repository](https://github.com/meta-llama/PurpleLlama/tree/main), which was extended — more on that in the [detailed section](#purplellama-changes).

### CodeGuard Structure

The CodeGuard directory structure is as follows:

```
CodeGuard/
├── api/
│   └── main.py
├── Eval/CyberSecEval4/
│   └── *.json
├── agents.py
├── config.yml
├── Dockerfile
├── requirements.txt
├── source.py
└── static_analysis.py
```

The `api` folder contains a simple FastAPI service with a main POST endpoint:

* `POST /run` — executes CodeGuard with optional runtime configuration

Configuration is defined via `config.yml`, for example:

```yml
llm:
  generator:
    provider: ollama
    model: gemma3:4b

  auditor:
    provider: ollama
    model: gemma3:4b

agents:
  use_auditor: true

execution:
  max_iterations: 3
```

The `agents.py` file contains implementations of agents responsible for:

* code generation
* security auditing
* code refinement

These are driven by structured prompts designed for secure code generation workflows.

---

### CodeGuard Pipeline Description

The main logic is implemented in `source.py` through the `CodeGuard` class.

The workflow can be summarized as:
1. **Initial Code Generation**
   The generator LLM produces code based on the input task.
2. **Static Analysis (SAST)**
   The generated code is analyzed using Bandit.
3. **Feedback Construction**
   * Static analysis results are formatted
   * Optionally enriched with LLM-based audit
4. **Iterative Refinement Loop**
   * Code is refined based on feedback
   * Loop continues until:
     * no improvement, or
     * iteration limit is reached
5. **Result Output**
   * final code
   * iteration count
   * full history of issues

The implementation also includes logging for:

* iteration progress
* issue counts
* convergence behavior

All components are fully dockerized for reproducibility and deployment.

---

## Evaluation Results on CyberSecEval4

### Instruct Benchmark

| Model | BLEU ↑ | Vulnerable % ↓ | Pass Rate ↑ |
|------|--------|----------------|-------------|
| gemini-3-flash-preview | **8.38 ↑** | 21.28 ↓ | 78.72 ↓ |
| gpt-5-mini | 4.15 ↓ | **12.06 ↑ (best baseline)** | **87.94 ↑ (best baseline)** |
| gemma3:4b | 6.80 ↑ | 21.63 ↓ | 78.37 ↓ |
| codeguard-gemma3:4b | **2.70 ↓** | **6.03 ↑ (best)** | **93.97 ↑ (best)** |

#### Observations

- GPT-5-mini is the strongest baseline in terms of security (~12% vulnerable)
- Gemini and Gemma show similar vulnerability (~21%)
- CodeGuard reduces vulnerabilities significantly (21.63% → 6.03%)
- Pass rate improves strongly (78.37% → 93.97%)
- BLEU drops again due to security-focused transformations


#### Conclusion

- Baseline models still produce insecure code (up to ~21%)
- CodeGuard consistently improves security regardless of model strength
- Even strong models (GPT-5-mini) are outperformed in security by CodeGuard

> CodeGuard confirms that iterative SAST + LLM refinement is more important than raw model capability for secure code generation

### Autocomplete Benchmark

| Model | BLEU ↑ | Vulnerable % ↓ | Pass Rate ↑ |
|------|--------|----------------|-------------|
| gemini-3-flash-preview | **20.44 ↑** | 43.59 ↓ | 56.41 ↓ |
| gpt-5-mini | 14.86 ↑ | 37.61 ↓ | 62.39 ↑ |
| gemma3:4b | 11.73 ↓ | 28.77 ↑ | 71.23 ↑ |
| codeguard-gemma3:4b | **3.62 ↓** | **5.13 ↑** | **94.87 ↑** |

---

#### Observations

- Higher BLEU ≠ better security (Gemini has best BLEU but worst vulnerability rate)
- Best baseline model: **gemma3:4b** (~29% vulnerable)
- **CodeGuard reduces vulnerabilities significantly** (28.77% → 5.13%)
- Pass rate improves strongly (71.23% → 94.87%)
- BLEU drops due to structural and security-focused modifications


#### Conclusion

CodeGuard introduces a clear trade-off:

- ↓ BLEU (less similarity to reference)
- ↑ Security (significant reduction in vulnerabilities)

Final takeaway:

> Raw LLMs generate insecure code frequently, while CodeGuard enables reliable and secure code generation even with smaller models.

---

## PurpleLlama Changes

### Scope of Benchmarks

Only the following benchmarks were used:

* `instruct`
* `autocomplete`

This is because other benchmarks are not directly related to secure code generation.

---

### Dataset Filtering

Both datasets were filtered to include only Python samples:

* [Instruct dataset](./PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct-v2.json)
* [Autocomplete dataset](./PurpleLlama/CybersecurityBenchmarks/datasets/autocomplete/autocomplete.json)

This was done for two main reasons:

1. The proposed solution relies heavily on SAST tools, which are language-specific

   * for Python → [Bandit](https://bandit.readthedocs.io/en/latest/)

2. Cost optimization

   * SOTA models (e.g., Gemini 3.1 Pro Preview, GPT-5.2) are paid
   * reducing dataset size makes experimentation more manageable

---

### Framework Extension

The benchmark framework was extended to support:

* Ollama models
* CodeGuard API as an LLM wrapper

Modifications in:

`./PurpleLlama/CybersecurityBenchmarks/benchmark/llm.py`

```python
from .llms.ollama import OLLAMA
from .llms.codeguard import CODEGUARD

...

if provider == "OLLAMA":
    return OLLAMA(config)
if provider == "CODEGUARD":
    return CODEGUARD(config)
```

---

### Running Benchmarks

#### CodeGuard Example

```
python3 -m CybersecurityBenchmarks.benchmark.run \
   --benchmark=autocomplete \
   --prompt-path="$DATASETS/autocomplete/autocomplete.json" \
   --response-path="$DATASETS/autocomplete_responses_codeguard_gemma3:4b.json" \
   --stat-path="$DATASETS/autocomplete_stat.json" \
   --llm-under-test=CODEGUARD::gemma3:4b-cloud::kakao::http://localhost:8000
```

> [!NOTE]
> First build the CodeGuard Docker image:
> [`./CodeGuard/Dockerfile`](./CodeGuard/Dockerfile)

---

#### Ollama Example

```
python3 -m CybersecurityBenchmarks.benchmark.run \
   --benchmark=instruct \
   --prompt-path="$DATASETS/instruct/instruct-v2.json" \
   --response-path="$DATASETS/instruct_responses_gpt-oss:120b-cloud.json" \
   --stat-path="$DATASETS/instruct_stat.json" \
   --llm-under-test=OLLAMA::gpt-oss:120b-cloud::kakao::http://localhost:11434
```

---

### OLLAMA Implementation

Implementation of the `OLLAMA` -> [`./PurpleLlama/CybersecurityBenchmarks/benchmark/llms/ollama.py`](./PurpleLlama/CybersecurityBenchmarks/benchmark/llms/ollama.py)

This implementation provides:

* local / remote Ollama API integration
* support for chat-style interaction
* configurable temperature and sampling

It acts as a bridge between the benchmark framework and locally hosted LLMs.

Full implementation:
```python
# pyre-strict

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests
from typing_extensions import override

from .llm_base import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_TEMPERATURE,
    DEFAULT_TOP_P,
    LLM,
    LLMConfig,
    UnretriableQueryException,
)

LOG: logging.Logger = logging.getLogger(__name__)


class OLLAMA(LLM):
    """Local Ollama client"""

    def __init__(self, config: LLMConfig) -> None:
        super().__init__(config)

        # Default local endpoint
        self.base_url: str = config.base_url or "http://localhost:11434"

    def _post(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=60,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise UnretriableQueryException(f"Ollama request failed: {e}")

    def _extract_response(self, response: Dict[str, Any]) -> str:
        try:
            content = response.get("message", {}).get("content", "")
        except Exception as e:
            raise UnretriableQueryException(
                f"Invalid Ollama response format: {e}, response={response}"
            )

        if not content:
            raise ValueError("Empty response from Ollama")

        return content

    def _build_messages(self, prompt_with_history: List[str]) -> List[Dict[str, str]]:
        messages: List[Dict[str, str]] = []

        for i in range(len(prompt_with_history)):
            role = "user" if i % 2 == 0 else "assistant"
            messages.append({"role": role, "content": prompt_with_history[i]})

        return messages

    @override
    def chat(
        self,
        prompt_with_history: List[str],
        guided_decode_json_schema: Optional[str] = None,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
    ) -> str:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": self._build_messages(prompt_with_history),
            "options": {
                "temperature": temperature,
                "top_p": top_p,
            },
            "stream": False,
        }

        response = self._post(payload)
        return self._extract_response(response)

    @override
    def chat_with_system_prompt(
        self,
        system_prompt: str,
        prompt_with_history: List[str],
        guided_decode_json_schema: Optional[str] = None,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
    ) -> str:
        messages = [{"role": "system", "content": system_prompt}]
        messages.extend(self._build_messages(prompt_with_history))

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "options": {
                "temperature": temperature,
                "top_p": top_p,
            },
            "stream": False,
        }

        response = self._post(payload)
        return self._extract_response(response)

    @override
    def query(
        self,
        prompt: str,
        guided_decode_json_schema: Optional[str] = None,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
    ) -> str:
        return self.chat([prompt], temperature=temperature, top_p=top_p)

    @override
    def query_with_system_prompt(
        self,
        system_prompt: str,
        prompt: str,
        guided_decode_json_schema: Optional[str] = None,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
    ) -> str:
        return self.chat_with_system_prompt(
            system_prompt,
            [prompt],
            temperature=temperature,
            top_p=top_p,
        )

    @override
    def valid_models(self) -> list[str]:
        return ["gemma3:4b", "deepseek-r1:8b"]

```

---

### CODEGUARD Implementation

Implementation of the `CODEGUARD` -> [`./PurpleLlama/CybersecurityBenchmarks/benchmark/llms/codeguard.py`](./PurpleLlama/CybersecurityBenchmarks/benchmark/llms/codeguard.py)

This component:

* wraps the CodeGuard API as an LLM interface
* forwards prompts to `/run` endpoint
* injects runtime configuration (model, provider, backend)
* returns refined secure code as final output

This allows CodeGuard to be evaluated **as if it were a standard LLM**, enabling direct comparison with baseline models.

Full implementation:
```python
# pyre-strict

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import requests
from typing_extensions import override

from .llm_base import (
    DEFAULT_TEMPERATURE,
    DEFAULT_TOP_P,
    LLM,
    LLMConfig,
    UnretriableQueryException,
)

LOG: logging.Logger = logging.getLogger(__name__)


class CODEGUARD(LLM):
    def __init__(self, config: LLMConfig) -> None:
        super().__init__(config)

        self.api_url: str = config.base_url or "http://localhost:8000"

        self.model: str = config.model
        self.backend_url: Optional[str] = config.base_url

    def _build_overrides(self) -> Dict[str, Any]:
        """
        Build CodeGuard overrides so that all agents use the same model/backend
        """

        return {
            "llm": {
                "generator": {
                    "provider": "ollama",
                    "model": self.model,
                    "base_url": self.backend_url,
                },
                "auditor": {
                    "provider": "ollama",
                    "model": self.model,
                    "base_url": self.backend_url,
                },
            }
        }

    def _post(self, prompt: str) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "task": prompt,
            "overrides": self._build_overrides(),
        }

        try:
            response = requests.post(
                f"{self.api_url}/run",
                json=payload,
                timeout=120,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise UnretriableQueryException(f"CodeGuard request failed: {e}")

    def _extract_response(self, response: Dict[str, Any]) -> str:
        try:
            return response["final_code"]
        except KeyError:
            raise UnretriableQueryException(
                f"Invalid CodeGuard response format: {response}"
            )

    @override
    def query(
        self,
        prompt: str,
        guided_decode_json_schema: Optional[str] = None,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
    ) -> str:
        response = self._post(prompt)
        return self._extract_response(response)

    @override
    def query_with_system_prompt(
        self,
        system_prompt: str,
        prompt: str,
        guided_decode_json_schema: Optional[str] = None,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
    ) -> str:
        combined_prompt = f"{system_prompt}\n\n{prompt}"
        return self.query(combined_prompt)

    @override
    def chat(
        self,
        prompt_with_history: List[str],
        guided_decode_json_schema: Optional[str] = None,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
    ) -> str:
        # flatten history into one prompt
        combined = "\n".join(prompt_with_history)
        return self.query(combined)

    @override
    def chat_with_system_prompt(
        self,
        system_prompt: str,
        prompt_with_history: List[str],
        guided_decode_json_schema: Optional[str] = None,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
    ) -> str:
        combined = system_prompt + "\n\n" + "\n".join(prompt_with_history)
        return self.query(combined)

    @override
    def valid_models(self) -> list[str]:
        return ["gemma3:4b", "deepseek-r1:8b", "qwen3:4b", "gpt-oss:120b-cloud"]
```

---

## Summary

The overall system introduces a layered approach:

```
LLM → Static Analysis → Feedback → Iterative Refinement → Secure Output
```

By integrating CodeGuard into PurpleLlama:

* raw LLMs can be compared with **secured LLM pipelines**
* vulnerability reduction can be measured directly
* the system becomes both an **evaluation framework** and a **practical security tool**
