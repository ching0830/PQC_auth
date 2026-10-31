"""Offline recomputation only; no new cryptographic samples."""
import json
from pathlib import Path
import statistics

from comparisons.old30.statistics import summarize

ROOT = Path(__file__).resolve().parents[1]


def recompute():
    old = ROOT/'comparisons/old30'
    samples = json.loads((old/'raw_samples.json').read_text())
    summary = summarize(samples, planned=30)
    if summary != json.loads((old/'summary.json').read_text()):
        raise ValueError('old30 raw integer timestamps/statistics disagree')
    opening = json.loads((ROOT/'comparisons/opening/results.json').read_text())
    checked = 0
    for name, record in opening['timings'].items():
        values = record['samples']
        expected = dict(count=len(values), min=min(values), max=max(values),
                        median=statistics.median(values), mean=statistics.mean(values),
                        nearest_rank_p95=sorted(values)[(95*len(values)+99)//100-1])
        if len(values) != 10 or any(record[key] != value for key, value in expected.items()):
            raise ValueError('opening statistics mismatch: '+name)
        checked += 1
    return dict(old30=dict(samples=len(samples), complete=summary['complete_samples'],
                          exactSummaryMatched=True, quantiles='Hyndman-Fan type 7'),
                independentOpening=dict(samples=10, warmupsExcluded=1, timingSeriesChecked=checked,
                                        quantiles='nearest-rank p95'),
                HplusFullAccessMeasured=False, newCryptographicExecutions=0)


if __name__ == '__main__':
    print(json.dumps(recompute(), sort_keys=True))
