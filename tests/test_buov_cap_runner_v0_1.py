"""Resource-policy regressions; no heavy jobs or physical pressure probes."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

path=Path(__file__).resolve().parents[1]/'benchmarks/buov_cap_research_v0_1/runner.py'
spec=importlib.util.spec_from_file_location('buov_runner_test_only',path)
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class ResourcePolicyTests(unittest.TestCase):
    def test_memory_minima_cannot_be_lowered(self):
        for key in ('start_available','stop_available'):
            with self.assertRaises(ValueError):r.validate_policy(dict(r.POLICY,**{key:1}))
        r.validate_policy(dict(r.POLICY,start_available=20<<30))

    def test_maxima_cannot_be_raised(self):
        for key in ('tree_rss','process_as','wall_seconds','file_bytes','directory_bytes'):
            with self.assertRaises(ValueError):r.validate_policy(dict(r.POLICY,**{key:r.POLICY[key]+1}))
        with self.assertRaises(ValueError):r.validate_policy(dict(r.POLICY,threads=True))

    def test_parallel_pilot_is_bounded_and_uses_distinct_physical_cores(self):
        with mock.patch.object(r,'CPU_POOL',(0,1,2,3,4,5)):
            for count in (1,2,4):
                r.validate_policy(dict(r.POLICY, threads=count))
                self.assertEqual(len(r.selected_cpus(count)), count)
        for count in (0,3,5,12):
            with self.assertRaises(ValueError):r.validate_policy(dict(r.POLICY,threads=count))
        row=dict(rss=1,virtual=1,threads=5)
        self.assertEqual(r.stop_reason([row],16<<30,0,0,0,0,dict(r.POLICY,threads=4)), 'threads')

    def test_topology_deduplicates_SMT_and_host_admission_is_separate(self):
        def topology(path):
            cpu=int(path.parents[1].name[3:])
            return '0' if path.name=='physical_package_id' else str({0:7,6:7,1:9,7:9}[cpu])
        with mock.patch.object(r.os,'sched_getaffinity',return_value={0,1,6,7}), mock.patch.object(Path,'read_text',topology):
            self.assertEqual(r.physical_cpu_pool(),(0,1))
        with mock.patch.object(r,'CPU_POOL',(4,5)):
            r.validate_policy(dict(r.POLICY,threads=4))
            with self.assertRaises(ValueError):r.selected_cpus(4)

    def test_admission_and_runtime_memory_boundaries(self):
        with self.assertRaises(RuntimeError):r.admit((16<<30)-1,0,0,r.POLICY)
        r.admit(16<<30,0,0,r.POLICY)
        self.assertEqual(r.stop_reason([], (8<<30)-1,0,0,0,0,r.POLICY),'MemAvailable')
        self.assertIsNone(r.stop_reason([],8<<30,0,0,0,0,r.POLICY))

    def test_directory_and_single_file_are_separate(self):
        with self.assertRaises(RuntimeError):r.admit(16<<30,10<<30,0,r.POLICY)
        with self.assertRaises(RuntimeError):r.admit(16<<30,2<<30,(1<<30)+1,r.POLICY)
        self.assertEqual(r.stop_reason([],16<<30,1801,0,0,0,r.POLICY),'wall_seconds')
