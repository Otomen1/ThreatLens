"""Release identity, separate from frozen scoring/engine versions."""

from importlib.metadata import PackageNotFoundError, version


def release_version() -> str:
    try:
        return version("threatlens")
    except PackageNotFoundError:
        # Vendored Vercel functions have no installed distribution metadata.
        return "1.2.0"
