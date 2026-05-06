from __future__ import annotations

from typing import Any

from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain_ollama import ChatOllama, OllamaEmbeddings
from langchain_openai import ChatOpenAI, OpenAIEmbeddings


def build_chat_llm(
    provider: str,
    model: str,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
) -> Any:
    provider_normalized = provider.lower()
    if provider_normalized == "ollama":
        return ChatOllama(model=model, base_url=base_url, temperature=0)
    if provider_normalized == "openai":
        return ChatOpenAI(model=model, base_url=base_url, api_key=api_key, temperature=0)
    if provider_normalized == "gemini":
        return ChatGoogleGenerativeAI(model=model, google_api_key=api_key, temperature=0)
    raise ValueError(f"Unsupported llm_provider={provider}. Allowed: ollama, openai, gemini.")


def build_embedder(
    provider: str,
    model: str,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
) -> Any:
    provider_normalized = provider.lower()
    if provider_normalized == "ollama":
        return OllamaEmbeddings(model=model, base_url=base_url)
    if provider_normalized == "openai":
        return OpenAIEmbeddings(model=model, base_url=base_url, api_key=api_key)
    if provider_normalized == "gemini":
        return GoogleGenerativeAIEmbeddings(model=model, google_api_key=api_key)
    raise ValueError(f"Unsupported llm_provider={provider}. Allowed: ollama, openai, gemini.")
