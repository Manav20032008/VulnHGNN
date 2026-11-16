from __future__ import annotations

from pathlib import Path


def find_project_root(start: Path | None = None) -> Path:
    """Directory containing pyproject.toml, or cwd if not found."""
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    return current


def load_project_env(start: Path | None = None) -> Path | None:
    """
    Load ``.env`` from the project root into ``os.environ``.

    Existing environment variables are not overwritten.
    Returns the path to the loaded file, or None if missing / dotenv unavailable.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return None

    root = find_project_root(start)
    env_path = root / ".env"
    if not env_path.is_file():
        return None

    load_dotenv(env_path, override=False)
    return env_path.resolve()
