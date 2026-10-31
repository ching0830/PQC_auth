"""Integer time/byte accounting; metadata checks, not crypto verification."""
MAIN = ('t_prep', 't_cap', 't_request_ready', 't_response_ready', 't_ticket_ready')
SEGMENTS = ('per_ticket_before_CAP_Init', 'UE_request', 'NCC_response', 'UE_completion')

def validate_and_derive(s):
    e = s['events_ns']
    if any(type(v) is not int for v in e.values()): raise ValueError('integer monotonic ns')
    times = [e[k] for k in MAIN]
    if any(b <= a for a,b in zip(times,times[1:])): raise ValueError('main event order')
    segments = dict(zip(SEGMENTS,(b-a for a,b in zip(times,times[1:])),strict=True))
    issuance = e['t_ticket_ready'] - e['t_cap']
    full = e['t_ticket_ready'] - e['t_prep']
    if sum(segments[k] for k in SEGMENTS[1:]) != issuance or sum(segments.values()) != full:
        raise ValueError('exact issuance conservation')
    if not (e['t_cap'] < e['cap_init_done'] <= e['message_prepare_start'] < e['message_prepare_done']
        <= e['witness_start'] < e['witness_done'] < e['t_request_ready']
        <= e['ncc_request_received'] <= e['ncc_preflight_start'] <= e['ncc_preflight_done']
        <= e['ncc_native_call_start'] < e['ncc_native_call_done'] <= e['inversion_start']
        < e['inversion_done'] <= e['inversion_postcondition_done'] <= e['t_response_ready']
        <= e['response_received'] < e['ticket_bytes_ready'] <= e['consumer_start']
        < e['consumer_done'] < e['t_ticket_ready']):
        raise ValueError('nested/cross-process event order')
    if e['ticket_release_ready'] != e['t_ticket_ready']: raise ValueError('real release endpoint')
    if s['counts'] != dict(CAP_Init=1,pi_iss_Prove=1,pi_iss_Verify=1,inversion=1,Append=1,pi2_Prove=1):
        raise ValueError('one genuine issuance')
    if (s['NCC']['UE_witness_received'] or s['NCC']['verification']['proof_Verify'] != 1
        or not s['NCC']['verification']['requests'][0]['accepted']): raise ValueError('recorded witness-free Verify')
    c = s['continuation']['consumer']
    if c['proof_Verify'] != 1 or not c['accepted'] or c['private_values_received']:
        raise ValueError('recorded independent consumer')
    n = s['normal_access']; m = n['event_ns']
    if (not n['completed'] or not n['session_keys_equal'] or n['cap_verify_calls'] != 1 or not n['cap_accepted']
        or not n['same_ticket_bytes'] or n['received_ticket'] != s['finalized']['ticket']):
        raise ValueError('recorded same-ticket ACTIVE')
    if n['state_returns'] != [dict(operation='reserve',state='RESERVED'),
        dict(operation='commit_grant',state='CONSUMED_PENDING_CONFIRM'),dict(operation='activate',state='CONSUMED_ACTIVE')]:
        raise ValueError('recorded committed state order')
    T12 = m['t_m2_done']-m['t_start']; T3 = m['t_active']-m['t_m2_done']
    access = m['t_active']-m['t_start']; gap = m['t_start']-e['t_ticket_ready']
    all_ns = m['t_active']-e['t_prep']
    if gap < 0 or T12 <= 0 or T3 <= 0 or T12+T3 != access or full+gap+T12+T3 != all_ns:
        raise ValueError('exact larger timeline conservation')
    return dict(segments_ns=segments,CAP_to_ticket_release_ns=issuance,including_per_ticket_prep_ns=full,
        consumer_nested_ns=e['consumer_done']-e['consumer_start'],
        ticket_bytes_to_release_ns=e['t_ticket_ready']-e['ticket_bytes_ready'],
        release_to_M1_start_gap_ns=gap,M1_M2_ns=T12,M3_extra_ns=T3,access_to_ACTIVE_ns=access,
        prep_to_ACTIVE_ns=all_ns,integer_conservation_passed=True,
        release_requires_consumer_and_final_checks=True,consumer_already_in_UE_completion=True)

def communication(s):
    v=s['finalized']; obs=s['IPC_observations']; w=s['normal_access']['wire_bytes']
    statement=s['statement']['bytes']; proof=s['proof']['bytes']
    return dict(statement_B=statement,pi_iss_B=proof,request_components_subtotal_B=statement+proof,
        request_protocol_wire='not defined by this research harness; component subtotal only',
        response_z_B=obs['z_bytes'],response_request_digest_B=obs['request_digest_bytes'],
        response_components_subtotal_B=obs['z_bytes']+obs['request_digest_bytes'],
        response_protocol_wire='not defined; request_digest is the local continuation binding',
        actual_benchmark_IPC=dict(request_B=obs['request_IPC_bytes'],response_B=obs['response_IPC_bytes'],
            classification='existing NCLI v2 canonical JSON/hex local framing; includes benchmark diagnostics; NOT protocol wire'),
        M_B=v['M']['bytes'],CR_B=v['CR']['bytes'],CZ_B=v['CZ']['bytes'],pi2_B=v['pi2']['bytes'],
        FinalTicket_B=v['ticket']['bytes'],M1_B=w['m1'],M2_B=w['m2'],M3_B=w['m3'],
        M1_M2_B=w['m1']+w['m2'],M1_M2_M3_B=w['m1']+w['m2']+w['m3'])
