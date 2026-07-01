"""Single source of truth for the package version at runtime.

Reads the installed distribution's version (stamped at build time from the
release tag), so ``__version__`` always matches the published package without a
manual bump here. Falls back to a local sentinel in a source checkout where the
distribution metadata isn't installed.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("securevector-sdk-langgraph")
except PackageNotFoundError:  # source/editable checkout, not pip-installed
    __version__ = "0.0.0+local"
