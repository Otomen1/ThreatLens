"""Process-wide Identity Intelligence runtime shared by all API routes."""

from .config import IdentityConfig
from .registry import build_default_registry
from .service import IdentityService

config = IdentityConfig.from_env()
registry = build_default_registry()
service = IdentityService(registry, config=config)
