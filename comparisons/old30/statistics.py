"""Recompute from raw ns. No cryptography, retries or discarded slow samples."""
from collections import Counter
from fractions import Fraction

from comparisons.old30.results import validate_and_derive


def quantile(values,p):
    ordered=sorted(values)
    if not ordered:raise ValueError('empty quantile')
    h=(len(ordered)-1)*Fraction(p)
    i=h.numerator//h.denominator
    return Fraction(ordered[i])+(h-i)*(ordered[min(i+1,len(ordered)-1)]-ordered[i])


def describe(values):
    if not values:return dict(n=0,mean=None,median=None,Q1=None,Q3=None,min=None,max=None)
    return dict(n=len(values),mean=float(sum(map(Fraction,values))/len(values)),
        median=float(quantile(values,Fraction(1,2))),Q1=float(quantile(values,Fraction(1,4))),
        Q3=float(quantile(values,Fraction(3,4))),min=min(values),max=max(values))


def issuance(s):
    e=s['events_ns']
    names=('t_prep','t_cap','t_request_ready','t_response_ready','ticket_release_ready')
    t=[e[k] for k in names]
    if any(type(x) is not int for x in t) or any(b<=a for a,b in zip(t,t[1:])):
        raise ValueError('raw issuance event order')
    parts=dict(zip(('per_ticket_before_CAP_Init','UE_request','NCC_response','UE_completion'),
        (b-a for a,b in zip(t,t[1:])),strict=True))
    if e['t_ticket_ready']!=e['ticket_release_ready']:raise ValueError('release endpoint')
    if not e['ticket_bytes_ready']<=e['consumer_start']<e['consumer_done']<t[-1]:
        raise ValueError('mandatory consumer release gate')
    if sum(parts.values())!=t[-1]-t[0] or sum(v for k,v in parts.items() if k!='per_ticket_before_CAP_Init')!=t[-1]-t[1]:
        raise ValueError('issuance integer conservation')
    return dict(**parts,CAP_to_ticket_release=t[-1]-t[1],including_per_ticket_prep=t[-1]-t[0],
        ticket_bytes_to_release=t[-1]-e['ticket_bytes_ready'])


def summarize(records,*,planned=30):
    if len({s['index'] for s in records})!=len(records):raise ValueError('duplicate attempt index')
    if [s['index'] for s in records]!=sorted(s['index'] for s in records):raise ValueError('sample order')
    if any(not 1<=s['index']<=planned for s in records):raise ValueError('unplanned attempt')
    released=[s for s in records if 'ticket_release_ready' in s['events_ns']]
    complete=[s for s in records if s['completed']]
    times={};nested={};sizes={};own=[]
    for s in released:
        for key,value in issuance(s).items():times.setdefault(key,[]).append(value)
    for s in complete:
        derived=validate_and_derive(s)
        if derived!=s['timing']:raise ValueError('saved timing differs from raw integers')
        for key in ('release_to_M1_start_gap_ns','M1_M2_ns','M3_extra_ns','access_to_ACTIVE_ns','prep_to_ACTIVE_ns'):
            times.setdefault(key.removesuffix('_ns'),[]).append(derived[key])
        for row in s['nested_timers']:
            value=row.get('elapsed_ns')
            if value is None:value=float(Fraction(str(row['raw_elapsed_seconds']))*10**9)
            nested.setdefault(row['name'],[]).append(value)
        for row in s['normal_access']['phase_events']:
            nested.setdefault('online_'+row['phase'],[]).append(row['elapsed_ns'])
        c=s['communication']
        for key,value in c.items():
            if type(value) is int:sizes.setdefault(key,[]).append(value)
        for key in ('request_B','response_B'):sizes.setdefault('benchmark_IPC_'+key,[]).append(c['actual_benchmark_IPC'][key])
        o=s['own_record'];own.append(o['end_ns']-o['start_ns'])
    # Distinct public evidence checks do not claim a proof of randomness quality.
    uniqueness={}
    for name,values in (
        ('holder_fingerprints',[s['finalized']['holder_public_key']['sha256'] for s in complete]),
        ('SN',[s['finalized']['SN'] for s in complete]),
        ('M_digests',[s['finalized']['M']['sha256'] for s in complete]),
        ('CR_digests',[s['finalized']['CR']['sha256'] for s in complete]),
        ('statements',[s['statement']['sha256'] for s in complete]),
        ('proofs',[s['proof']['sha256'] for s in complete]),
        ('SID',[s['own_record']['records']['SID'] for s in complete])):
        uniqueness[name]=len(set(values))==len(values)
        if not uniqueness[name]:raise ValueError('unexpected cross-request reuse: '+name)
    groups=Counter((s['communication']['frontier_seed_count'],s['communication']['pi2_B'],
        s['communication']['FinalTicket_B'],s['communication']['M1_B']) for s in complete)
    return dict(schema='PQSATFreshIssuanceStatisticsV1',planned_attempts=planned,
        records=len(records),released_samples=len(released),complete_samples=len(complete),
        failed_indices=[s['index'] for s in records if not s['completed']],
        quartile_method='Hyndman-Fan type 7; h=(n-1)*p; interpolate sorted raw ns before display rounding',
        time_unit='ns',size_unit='B; frontier_seed_count is a count',
        times={k:describe(v) for k,v in times.items()},nested={k:describe(v) for k,v in nested.items()},
        sizes={k:describe(v) for k,v in sizes.items()},own_record_preparation=describe(own),
        size_groups=[dict(frontier_seed_count=k[0],pi2_B=k[1],Ticket_B=k[2],M1_B=k[3],count=v) for k,v in sorted(groups.items())],
        distinct_public_evidence=uniqueness,integer_conservation_all_complete=True,
        ordered_attempt_indices=[s['index'] for s in records])
