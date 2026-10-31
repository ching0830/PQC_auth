"""Explicit, incompatible H-chi-plus research profile; never a production adapter.

Unchanged CAP modules are loaded under THIS package's namespace from the pinned
v0.1 sources. Their relative imports resolve to our parameters/field/native
opening modules. No legacy module, sys.modules entry, or global is patched.
"""
from .source_boundary import check_reused_sources

# This is a closed source overlay, not an environment-dependent plugin search.
__path__.append(str(check_reused_sources()))
from .parameters import load_profile_manifest
