"""Zero-config global install: ``import securevector_sdk_langgraph.auto``.

Reads ``SECUREVECTOR_SDK_MODE`` (default ``observe``) from the environment and
registers a global handler so every LangChain chain/agent in the process is
instrumented with no per-call wiring. All other settings come from the same
environment variables documented in :mod:`securevector_sdk_langgraph.config`.
"""

import os

from . import install

install(mode=os.environ.get("SECUREVECTOR_SDK_MODE", "observe"), register_global=True)
