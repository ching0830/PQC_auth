"""Explicit full-profile legacy CAP optimization; research-only, unqualified.

Import never compiles, loads or discovers a native library. The oracle remains
unchanged. Call NativeCAPProver.load with an absolute path and SHA-256.
"""
from .kernel import NativeCAPProver, NativeProverError
__all__ = ('NativeCAPProver','NativeProverError')
