import os
from dotenv import load_dotenv

load_dotenv()


def create_llm(provider: str, model: str, temperature: float = 0):
    provider = provider.lower()

    if provider == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=model, temperature=temperature, api_key=os.getenv("OPENAI_API_KEY")
        )

    elif provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI

        return ChatGoogleGenerativeAI(
            model=model,
            temperature=temperature,
            google_api_key=os.getenv("GOOGLE_API_KEY"),
        )

    elif provider == "ollama":
        from langchain_community.chat_models import ChatOllama

        return ChatOllama(
            model=model,
            temperature=temperature,
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        )

    else:
        raise ValueError(f"Unsupported provider: {provider}")


def generate_code(llm, task: str):
    prompt = f"""
You are a senior secure software engineer.

Your task:
{task}

Requirements:
- Follow OWASP secure coding practices
- Validate and sanitize all external inputs
- Use safe libraries and avoid insecure defaults
- Handle errors safely (no sensitive data leakage)
- Use least-privilege principles where applicable

Constraints:
- Do NOT include explanations
- Do NOT include markdown
- Return ONLY valid, runnable code
- Prefer clarity and security over brevity

Output:
Return only the code.
"""
    return llm.invoke(prompt).content


def audit_code(llm, code: str):
    prompt = f"""
You are a security auditor reviewing code.

Analyze the following code for security vulnerabilities:

{code}

Focus on:
- Injection risks (SQL, command, etc.)
- Unsafe deserialization or execution
- Weak cryptography
- Hardcoded secrets
- Input validation issues
- Misuse of system calls or libraries

Output format:
- If no issues: SAFE
- Otherwise: list each issue with:
  [SEVERITY] description → fix

Be precise and do not hallucinate.
"""
    return llm.invoke(prompt).content


def refine_code(llm, code: str, feedback: str):
    prompt = f"""
You are a secure code remediation expert.

Task:
Fix the code based on the security findings below.

Security findings:
{feedback}

Original code:
{code}

Requirements:
- Fix ALL reported vulnerabilities
- Do NOT introduce new vulnerabilities
- Preserve original functionality
- Improve input validation and error handling where needed

Constraints:
- Do NOT include explanations
- Do NOT include markdown
- Return ONLY the corrected code

Output:
Return only the improved secure code.
"""
    return llm.invoke(prompt).content
