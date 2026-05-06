from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx
from bs4 import BeautifulSoup
from langchain_community.document_loaders import PyPDFLoader


@dataclass
class IngestedDocument:
    source_id: str
    source_uri: str
    source_type: str
    content: str
    last_updated: str | None
    etag: str | None
    content_hash: str


class IngestionService:
    def __init__(self, timeout_seconds: int = 20) -> None:
        self.timeout_seconds = timeout_seconds

    def load_pdfs(self, pdf_paths: list[str]) -> list[IngestedDocument]:
        docs: list[IngestedDocument] = []
        for pdf_path in pdf_paths:
            loader = PyPDFLoader(pdf_path)
            pages = loader.load()
            text = "\n".join(page.page_content for page in pages)
            content_hash = self._hash(text)
            docs.append(
                IngestedDocument(
                    source_id=f"pdf:{Path(pdf_path).name}",
                    source_uri=pdf_path,
                    source_type="pdf",
                    content=text,
                    last_updated=datetime.now(timezone.utc).isoformat(),
                    etag=None,
                    content_hash=content_hash,
                )
            )
        return docs

    def load_urls(self, urls: list[str]) -> list[IngestedDocument]:
        docs: list[IngestedDocument] = []
        with httpx.Client(timeout=self.timeout_seconds, follow_redirects=True) as client:
            for url in urls:
                response = client.get(url)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, "html.parser")
                text = soup.get_text(separator=" ", strip=True)
                content_hash = self._hash(text)
                docs.append(
                    IngestedDocument(
                        source_id=f"url:{hashlib.sha256(url.encode('utf-8')).hexdigest()[:12]}",
                        source_uri=url,
                        source_type="url",
                        content=text,
                        last_updated=response.headers.get("Last-Modified"),
                        etag=response.headers.get("ETag"),
                        content_hash=content_hash,
                    )
                )
        return docs

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

