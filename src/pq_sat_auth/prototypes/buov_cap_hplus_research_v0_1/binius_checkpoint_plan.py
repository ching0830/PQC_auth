"""Explicit unmerged diagnostic profile: source components, never an RSS bound."""

from ..buov_cap_research_v0_1.binius_workspace_plan import pool_capacity


def checkpoint_plan(counts, setup, setup_rss, *, regenerated_masks=False, query_target=128):
    if type(regenerated_masks) is not bool:
        raise ValueError('explicit tested mask storage profile')
    if regenerated_masks and setup.get('prover_memory_profile')!='checkpoint4/on_the_fly/no_pool_retention/regenerated_private_masks/v0.1':
        raise ValueError('setup must bind the actual regenerated-mask profile')
    if type(query_target) is not int or query_target != 128:
        raise ValueError('explicit supported query target')
    q, lengths, arities = ((232, [786, 9933087, 98638, 512], [4, 4, 4, 3]) if query_target == 96
                           else (309, [863, 9933087, 98715, 512], [4, 4, 3, 3]))
    if (setup['security_bits'], setup['log_inv_rate'], setup['n_test_queries']) != (query_target, 1, q):
        raise ValueError('fixed query target and rate')
    specs = setup['merged']
    if (len(specs) != 4 or [s['log_msg_len'] for s in specs] != [10, 24, 17, 9]
            or setup['rounds'] != [[s] for s in specs]
            or any(s['is_zk'] is not True for s in specs)
            or [s['len'] for s in specs] != lengths or setup['fold_arities'] != arities
            or setup['max_log_domain_size'] != 25):
        raise ValueError('actual complete unmerged masked shape')
    if (counts['AND'], counts['ZERO'], counts['private_words'], counts['native_len_bytes']) != (
            16361386, 3263533, 19866173, 872897760):
        raise ValueError('complete pinned relation shape')
    if type(setup_rss) is not int or not 0 < setup_rss < 2 << 30:
        raise ValueError('measured public setup RSS')
    oracles = []
    for spec in specs:
        message = 16 << spec['log_msg_len']
        leaves = message // 8  # codeword=4M; each masked leaf=2 GF128=32B
        checkpoint = ((2 * (leaves >> 4)) - 1) * 32
        oracles.append(dict(message_bytes=message, mask_bytes=message,
            mask_persistent_bytes=32 if regenerated_masks else message,
            codeword_bytes=4 * message, checkpoint_tree_logical_bytes=checkpoint,
            checkpoint_pool_capacity_bytes=pool_capacity(checkpoint)))
    persistent = sum(o['message_bytes'] + o['mask_persistent_bytes'] + o['codeword_bytes']
                     + o['checkpoint_pool_capacity_bytes'] for o in oracles)
    # Public words include constants. Conservative extra word covers ValueVec layout padding.
    values = 8 * (counts['constants'] + counts['public_words'] + counts['private_words'] + 1)
    and_peak = (2 * pool_capacity(8 * counts['AND'])
                + 3 * pool_capacity(16 * counts['AND']))
    hidden = pool_capacity(16 * counts['private_words'])
    public = pool_capacity(16 * (counts['constants'] + counts['public_words']))
    phase2_peak = 2 * hidden + 2 * public  # prepared tensor dropped before word folding
    transient = max(and_peak, phase2_peak)
    # Setup RSS is a real single sample, not a replacement for later monitoring.
    # Margin covers unclosed outer transpose, controller and allocator costs.
    margin = 192 << 20
    projection = setup_rss + values + persistent + transient + margin
    return dict(schema='BUOVCAPBiniusCheckpointPlanV1',
        classification='source components plus sampled setup RSS and explicit heuristic margin; not a formal RSS bound',
        profile='research_unmerged_checkpoint_v0_1', query_target_bits=query_target, oracles=oracles,
        all_oracle_persistent_components_bytes=persistent,
        regenerated_masks=regenerated_masks,
        temporary_regenerated_mask_max_bytes=max(o['mask_bytes'] for o in oracles) if regenerated_masks else 0,
        ValueVec_component_bytes=values, AND_transient_components_bytes=and_peak,
        phase2_transient_components_bytes=phase2_peak, measured_public_setup_RSS_bytes=setup_rss,
        heuristic_margin_bytes=margin, projected_with_margin_bytes=projection,
        monitoring_stop_bytes=4 << 30, full_Prove_admitted=projection < (4 << 30),
        assumptions=['same explicit unmerged actual setup', 'height4 top-only Merkle checkpoints',
                     'same-basis OnTheFly NTT', 'no retained pool free blocks',
                     'phase2 releases prepared tensor before folded witness allocation']
                    + (['fresh private seed per oracle, exact mask regenerated transiently'] if regenerated_masks else []),
        unknown=['outer prover transpose exact allocation', 'global allocator release behaviour',
                 'complete measured proof RSS/time', 'full proof IP messages',
                 'changed query openings/FRI terminal and cap transient allocations'],
        full_proof_body_bytes=None, FRI_component_exact_format_bytes=setup['FRI_component_exact_format_bytes'],
        full_Prove_seconds=None, full_Verify_seconds=None)
