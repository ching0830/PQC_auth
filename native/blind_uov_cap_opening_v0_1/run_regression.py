"""Run the requested prototype discovery with legacy build outputs isolated.

The existing native-relation tests otherwise write their fixed legacy /tmp
build directory. Relocate that test build module's BUILD before test import;
no source, kernel, oracle or test behavior changes. No timing uses this runner.
"""
import runpy
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from native.blind_uov_cap_v0_1 import build
build.BUILD = Path('/tmp/pqsat_cap_native_opening_build_v0_1/legacy_regression')
sys.argv = ['unittest', 'discover', '-s', 'tests/prototypes/blind_uov_pqsat_v0_1', '-p', 'test_*.py', '-v']
runpy.run_module('unittest', run_name='__main__')
