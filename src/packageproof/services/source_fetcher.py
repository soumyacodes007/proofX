from __future__ import annotations

import io
import tarfile
import zipfile

import httpx

from packageproof.core.config import Settings
from packageproof.models.schemas import AnalyzePackageRequest, RegistryResult, SourceArchive

TEXT_EXTENSIONS = {
    "",
    ".cjs",
    ".cfg",
    ".ini",
    ".js",
    ".json",
    ".mjs",
    ".py",
    ".pyi",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


class SourceFetcher:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def fetch(
        self,
        request: AnalyzePackageRequest,
        registry: RegistryResult,
    ) -> SourceArchive:
        if not registry.source_url:
            return SourceArchive(errors=["no source archive URL found"])

        try:
            async with httpx.AsyncClient(timeout=self.settings.http_timeout_seconds) as client:
                response = await client.get(registry.source_url)
                response.raise_for_status()
                content = response.content
        except Exception as exc:
            return SourceArchive(errors=[f"source archive download failed: {exc}"])

        if len(content) > self.settings.max_archive_bytes:
            return SourceArchive(
                truncated=True,
                errors=["source archive exceeds phase 1 size limit"],
            )

        if request.ecosystem == "npm" or registry.source_url.endswith((".tgz", ".tar.gz")):
            return self._extract_tar(content)
        if registry.source_url.endswith(".whl") or registry.source_url.endswith(".zip"):
            return self._extract_zip(content)
        return SourceArchive(errors=["unsupported source archive format"])

    def _extract_tar(self, content: bytes) -> SourceArchive:
        archive = SourceArchive()
        try:
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as tar:
                for member in tar:
                    if len(archive.files) >= self.settings.max_static_files:
                        archive.truncated = True
                        break
                    if not member.isfile():
                        continue
                    if not self._looks_text(member.name):
                        continue
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        continue
                    archive.files[member.name] = self._decode_text(extracted.read(256_000))
        except Exception as exc:
            archive.errors.append(f"tar extraction failed: {exc}")
        return archive

    def _extract_zip(self, content: bytes) -> SourceArchive:
        archive = SourceArchive()
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zipped:
                for name in zipped.namelist():
                    if len(archive.files) >= self.settings.max_static_files:
                        archive.truncated = True
                        break
                    if name.endswith("/") or not self._looks_text(name):
                        continue
                    archive.files[name] = self._decode_text(zipped.read(name)[:256_000])
        except Exception as exc:
            archive.errors.append(f"zip extraction failed: {exc}")
        return archive

    @staticmethod
    def _looks_text(path: str) -> bool:
        suffix = "." + path.rsplit(".", maxsplit=1)[-1].lower() if "." in path else ""
        interesting_names = {
            "package.json",
            "setup.py",
            "pyproject.toml",
            "sitecustomize.py",
            "usercustomize.py",
        }
        return suffix in TEXT_EXTENSIONS or path.rsplit("/", maxsplit=1)[-1] in interesting_names

    @staticmethod
    def _decode_text(content: bytes) -> str:
        return content.decode("utf-8", errors="replace")
