from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from packageproof.core.config import Settings
from packageproof.models.schemas import AnalyzePackageRequest, RegistryResult
from packageproof.services.name_attack import NameAttackDetector


class RegistryClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def inspect(self, request: AnalyzePackageRequest) -> RegistryResult:
        if request.ecosystem == "npm":
            result = await self._inspect_npm(request)
        else:
            result = await self._inspect_pypi(request)

        osv_version = result.resolved_version
        if not osv_version and request.version != "latest":
            osv_version = request.version
        if osv_version:
            result.advisories = await self._query_osv(request, osv_version)
        result.metadata["reputation"] = self._reputation_signals(result)
        result.metadata["name_attack"] = NameAttackDetector().analyze(request, result)
        return result

    async def _inspect_npm(self, request: AnalyzePackageRequest) -> RegistryResult:
        encoded = quote(request.package, safe="@")
        url = f"https://registry.npmjs.org/{encoded}"
        result = RegistryResult(
            ecosystem=request.ecosystem,
            package=request.package,
            requested_version=request.version,
        )
        try:
            async with httpx.AsyncClient(timeout=self.settings.http_timeout_seconds) as client:
                response = await client.get(url)
                if response.status_code == 404:
                    result.errors.append("package not found in npm registry")
                    return result
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            result.errors.append(f"npm registry lookup failed: {exc}")
            return result

        versions: dict[str, Any] = data.get("versions", {})
        resolved = request.version
        if request.version == "latest":
            resolved = data.get("dist-tags", {}).get("latest", "")
        version_info = versions.get(resolved, {})
        previous_version = self._previous_npm_version(data, resolved)
        previous_info = versions.get(previous_version or "", {})
        result.exists = bool(version_info)
        result.resolved_version = resolved or None
        result.source_url = version_info.get("dist", {}).get("tarball")
        result.metadata = {
            "name": data.get("name"),
            "description": data.get("description"),
            "dist_tags": data.get("dist-tags", {}),
            "created": data.get("time", {}).get("created"),
            "modified": data.get("time", {}).get("modified"),
            "version_time": data.get("time", {}).get(resolved),
            "maintainers": data.get("maintainers", []),
            "repository": data.get("repository"),
            "license": data.get("license") or version_info.get("license"),
            "scripts": version_info.get("scripts", {}),
            "dependencies": version_info.get("dependencies", {}),
            "dev_dependencies": version_info.get("devDependencies", {}),
            "peer_dependencies": version_info.get("peerDependencies", {}),
            "bin": version_info.get("bin"),
            "homepage": data.get("homepage") or version_info.get("homepage"),
            "bugs": data.get("bugs") or version_info.get("bugs"),
            "dist": {
                "integrity": version_info.get("dist", {}).get("integrity"),
                "shasum": version_info.get("dist", {}).get("shasum"),
                "unpacked_size": version_info.get("dist", {}).get("unpackedSize"),
            },
            "version_diff": self._npm_version_diff(previous_version, previous_info, version_info),
            "provenance": self._npm_provenance_signals(version_info),
        }
        if not result.exists:
            result.errors.append(f"version {request.version} not found in npm registry")
        return result

    async def _inspect_pypi(self, request: AnalyzePackageRequest) -> RegistryResult:
        url = f"https://pypi.org/pypi/{quote(request.package)}/json"
        result = RegistryResult(
            ecosystem=request.ecosystem,
            package=request.package,
            requested_version=request.version,
        )
        try:
            async with httpx.AsyncClient(timeout=self.settings.http_timeout_seconds) as client:
                response = await client.get(url)
                if response.status_code == 404:
                    result.errors.append("package not found in PyPI")
                    return result
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            result.errors.append(f"PyPI lookup failed: {exc}")
            return result

        info = data.get("info", {})
        resolved = info.get("version") if request.version == "latest" else request.version
        releases = data.get("releases", {})
        files = releases.get(resolved, [])
        previous_version = self._previous_pypi_version(data, resolved)
        previous_files = releases.get(previous_version or "", [])
        result.exists = bool(files) or request.version == "latest"
        result.resolved_version = resolved
        result.source_url = self._best_pypi_source(files)
        result.metadata = {
            "name": info.get("name"),
            "summary": info.get("summary"),
            "version": info.get("version"),
            "author": info.get("author"),
            "maintainer": info.get("maintainer"),
            "home_page": info.get("home_page"),
            "project_urls": info.get("project_urls"),
            "license": info.get("license"),
            "requires_dist": info.get("requires_dist"),
            "classifiers": info.get("classifiers"),
            "release_files": [
                {
                    "filename": item.get("filename"),
                    "packagetype": item.get("packagetype"),
                    "upload_time_iso_8601": item.get("upload_time_iso_8601"),
                    "size": item.get("size"),
                }
                for item in files
            ],
            "version_upload_time": self._first_upload_time(files),
            "version_diff": self._pypi_version_diff(previous_version, previous_files, files),
            "provenance": self._pypi_provenance_signals(info, files),
        }
        if not result.exists:
            result.errors.append(f"version {request.version} not found in PyPI")
        return result

    async def _query_osv(
        self,
        request: AnalyzePackageRequest,
        resolved_version: str,
    ) -> list[dict[str, Any]]:
        ecosystem = "PyPI" if request.ecosystem == "pypi" else "npm"
        payload = {
            "package": {"name": request.package, "ecosystem": ecosystem},
            "version": resolved_version,
        }
        try:
            async with httpx.AsyncClient(timeout=self.settings.http_timeout_seconds) as client:
                response = await client.post("https://api.osv.dev/v1/query", json=payload)
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            return [{"source": "osv", "error": str(exc)}]

        advisories = []
        for vuln in data.get("vulns", []):
            vuln_id = str(vuln.get("id", ""))
            if vuln_id.startswith("MAL-") or "malicious" in str(vuln).lower():
                advisory_type = "malicious"
            else:
                advisory_type = "vulnerability"
            advisories.append(
                {
                    "source": "osv",
                    "id": vuln_id,
                    "type": advisory_type,
                    "summary": vuln.get("summary"),
                    "aliases": vuln.get("aliases", []),
                }
            )
        return advisories

    @staticmethod
    def _best_pypi_source(files: list[dict[str, Any]]) -> str | None:
        for preferred in ("sdist", "bdist_wheel"):
            for item in files:
                if item.get("packagetype") == preferred:
                    return item.get("url")
        return files[0].get("url") if files else None

    @staticmethod
    def _first_upload_time(files: list[dict[str, Any]]) -> str | None:
        times = [
            item.get("upload_time_iso_8601") or item.get("upload_time")
            for item in files
            if item.get("upload_time_iso_8601") or item.get("upload_time")
        ]
        return sorted(times)[0] if times else None

    def _reputation_signals(self, result: RegistryResult) -> dict[str, Any]:
        signals: list[dict[str, str]] = []
        metadata = result.metadata

        package_age_days = self._age_days(metadata.get("created"))
        version_time = metadata.get("version_time") or metadata.get("version_upload_time")
        version_age_days = self._age_days(version_time)
        maintainer_count = len(metadata.get("maintainers") or [])
        dependency_count = len(metadata.get("dependencies") or {}) + len(
            metadata.get("requires_dist") or []
        )

        if package_age_days is not None and package_age_days < 14:
            signals.append(
                {
                    "type": "new_package",
                    "severity": "medium",
                    "detail": f"Package was first published {package_age_days} days ago",
                }
            )
        if version_age_days is not None and version_age_days < 3:
            signals.append(
                {
                    "type": "fresh_release",
                    "severity": "low",
                    "detail": f"Analyzed version was published {version_age_days} days ago",
                }
            )
        if not metadata.get("repository") and not metadata.get("project_urls"):
            signals.append(
                {
                    "type": "missing_source_repository",
                    "severity": "low",
                    "detail": "No source repository metadata found",
                }
            )
        if result.ecosystem == "npm" and maintainer_count == 0:
            signals.append(
                {
                    "type": "missing_maintainer_metadata",
                    "severity": "low",
                    "detail": "No npm maintainer metadata found",
                }
            )
        if dependency_count >= 50:
            signals.append(
                {
                    "type": "large_dependency_surface",
                    "severity": "low",
                    "detail": f"Package declares {dependency_count} dependency entries",
                }
            )
        for signal in metadata.get("version_diff", {}).get("signals", []):
            signals.append(signal)
        for signal in metadata.get("provenance", {}).get("signals", []):
            signals.append(signal)

        return {
            "package_age_days": package_age_days,
            "version_age_days": version_age_days,
            "maintainer_count": maintainer_count,
            "dependency_count": dependency_count,
            "signals": signals,
        }

    @staticmethod
    def _previous_npm_version(data: dict[str, Any], resolved: str) -> str | None:
        times = data.get("time", {})
        ordered = sorted(
            (value, key)
            for key, value in times.items()
            if key not in {"created", "modified"} and key != resolved
        )
        resolved_time = times.get(resolved)
        if resolved_time:
            before = [version for time, version in ordered if time < resolved_time]
            return before[-1] if before else None
        return ordered[-1][1] if ordered else None

    @staticmethod
    def _previous_pypi_version(data: dict[str, Any], resolved: str) -> str | None:
        releases = data.get("releases", {})
        candidates: list[tuple[str, str]] = []
        resolved_time = None
        for version, files in releases.items():
            upload_time = RegistryClient._first_upload_time(files)
            if not upload_time:
                continue
            if version == resolved:
                resolved_time = upload_time
            else:
                candidates.append((upload_time, version))
        candidates.sort()
        if resolved_time:
            before = [version for time, version in candidates if time < resolved_time]
            return before[-1] if before else None
        return candidates[-1][1] if candidates else None

    @staticmethod
    def _npm_version_diff(
        previous_version: str | None,
        previous_info: dict[str, Any],
        version_info: dict[str, Any],
    ) -> dict[str, Any]:
        signals: list[dict[str, str]] = []
        previous_scripts = set((previous_info.get("scripts") or {}).keys())
        current_scripts = set((version_info.get("scripts") or {}).keys())
        added_scripts = sorted(
            (current_scripts - previous_scripts)
            & {"preinstall", "install", "postinstall", "prepare"}
        )
        previous_bins = set(RegistryClient._bin_names(previous_info.get("bin")))
        current_bins = set(RegistryClient._bin_names(version_info.get("bin")))
        added_bins = sorted(current_bins - previous_bins)
        previous_deps = set((previous_info.get("dependencies") or {}).keys())
        current_deps = set((version_info.get("dependencies") or {}).keys())
        added_deps = sorted(current_deps - previous_deps)

        if added_scripts:
            signals.append(
                {
                    "type": "new_lifecycle_script",
                    "severity": "high",
                    "detail": f"New lifecycle scripts vs {previous_version}: {added_scripts}",
                }
            )
        if len(added_bins) >= 3:
            signals.append(
                {
                    "type": "new_cli_surface",
                    "severity": "low",
                    "detail": f"New CLI bins vs {previous_version}: {added_bins[:5]}",
                }
            )
        if len(added_deps) >= 10:
            signals.append(
                {
                    "type": "dependency_spike",
                    "severity": "low",
                    "detail": f"{len(added_deps)} new dependencies vs {previous_version}",
                }
            )
        return {
            "previous_version": previous_version,
            "added_scripts": added_scripts,
            "added_bins": added_bins,
            "added_dependencies": added_deps[:50],
            "signals": signals,
        }

    @staticmethod
    def _pypi_version_diff(
        previous_version: str | None,
        previous_files: list[dict[str, Any]],
        files: list[dict[str, Any]],
    ) -> dict[str, Any]:
        previous_types = {item.get("packagetype") for item in previous_files}
        current_types = {item.get("packagetype") for item in files}
        added_types = sorted(str(item) for item in current_types - previous_types if item)
        signals = []
        if "bdist_wheel" in added_types and previous_version:
            signals.append(
                {
                    "type": "new_binary_distribution",
                    "severity": "medium",
                    "detail": f"Wheel distribution newly appeared vs {previous_version}",
                }
            )
        return {
            "previous_version": previous_version,
            "added_distribution_types": added_types,
            "signals": signals,
        }

    @staticmethod
    def _npm_provenance_signals(version_info: dict[str, Any]) -> dict[str, Any]:
        dist = version_info.get("dist") or {}
        signals = []
        if not dist.get("integrity"):
            signals.append(
                {
                    "type": "missing_npm_integrity",
                    "severity": "low",
                    "detail": "npm dist integrity metadata is missing",
                }
            )
        return {"signals": signals}

    @staticmethod
    def _pypi_provenance_signals(
        info: dict[str, Any],
        files: list[dict[str, Any]],
    ) -> dict[str, Any]:
        signals = []
        project_urls = info.get("project_urls") or {}
        home_page = info.get("home_page")
        if not project_urls and not home_page:
            signals.append(
                {
                    "type": "missing_project_links",
                    "severity": "low",
                    "detail": "PyPI package has no homepage or project URLs",
                }
            )
        if files and not any(item.get("digests", {}).get("sha256") for item in files):
            signals.append(
                {
                    "type": "missing_file_digest",
                    "severity": "low",
                    "detail": "PyPI release file digest metadata is missing",
                }
            )
        return {"signals": signals}

    @staticmethod
    def _bin_names(value: Any) -> list[str]:
        if isinstance(value, str):
            return ["default"]
        if isinstance(value, dict):
            return [str(key) for key in value]
        return []

    @staticmethod
    def _age_days(value: str | None) -> int | None:
        if not value:
            return None
        normalized = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return max((datetime.now(UTC) - parsed).days, 0)
