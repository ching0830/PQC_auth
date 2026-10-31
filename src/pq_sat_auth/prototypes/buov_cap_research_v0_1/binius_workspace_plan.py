"""Source-derived merged-oracle storage; never a full RSS or time bound.

The exact symbolic ZK setup supplies the real grouping. BufferPool rounds
allocations to powers of two and retains freed blocks. No proof is admitted
by this accounting: later oracles, retained pool blocks and opening remain.
"""


def _positive(value, name):
    if type(value) is not int or not 0 < value <= 1 << 40:
        raise ValueError(name + ' bounded positive integer')
    return value


def pool_capacity(size):
    return 1 << (_positive(size, 'size') - 1).bit_length()


def workspace_plan(counts, setup):
    cs = _positive(counts['native_len_bytes'], 'CS logical size')
    rounds = setup['rounds']
    if not rounds or not rounds[0]:
        raise ValueError('nonempty first ZK round')
    first = rounds[0]
    for spec in first:
        if (type(spec['log_msg_len']) is not int or not 2 <= spec['log_msg_len'] <= 30
                or type(spec['is_zk']) is not bool):
            raise ValueError('full-profile oracle shape')
    if not any(spec['is_zk'] for spec in first):
        raise ValueError('first round must remain masked')
    if (type(setup['log_inv_rate']) is not int or type(setup['security_bits']) is not int
            or setup['log_inv_rate'] != 1 or setup['security_bits'] != 96):
        raise ValueError('fixed diagnostic parameters')
    original = sum(16 << spec['log_msg_len'] for spec in first)
    merged_log = ((original // 16) - 1).bit_length()
    if setup['merged'][0]['log_msg_len'] != merged_log or not setup['merged'][0]['is_zk']:
        raise ValueError('exact symbolic setup/grouping mismatch')
    message = 16 << merged_log
    mask = message
    codeword = 4 * message  # equal mask, batch1, inverse-rate2
    leaves = codeword // 32  # two GF128 elements per ZK leaf
    tree_logical = (2 * leaves - 1) * 32
    tree_capacity = pool_capacity(tree_logical)
    originals_retained = original if len(first) > 1 else 0
    simultaneous = originals_retained + message + mask + codeword + tree_capacity
    domain = setup['max_log_domain_size']
    if type(domain) is not int or not merged_log + 1 <= domain <= 31:
        raise ValueError('bounded actual NTT domain')
    return dict(schema='BUOVCAPBiniusWorkspacePlanV1',
        classification='source-derived allocation components; NOT measured full RSS or formal bound',
        first_round_constituents=len(first), merged_log_msg_len=merged_log,
        original_message_bytes_retained=originals_retained,
        merged_message_bytes=message, merged_mask_bytes=mask,
        codeword_bytes=codeword, concatenation_temporary_bytes=0,
        concatenation_bytes_avoided=2 * message,
        merkle_leaf_count=leaves, merkle_nodes_logical_bytes=tree_logical,
        merkle_pool_capacity_bytes=tree_capacity,
        simultaneous_first_commit_components_bytes=simultaneous,
        shared_CS_logical_bytes=cs,
        CS_and_first_commit_components_bytes=cs + simultaneous,
        NTT_initialized_bytes=16 << (domain - 1),
        NTT_reserved_bytes=16 << domain,
        monitoring_stop_bytes=4 << 30, per_process_AS_limit_bytes=8 << 30,
        full_Prove_admitted=False, full_Verify_executed=False,
        omitted=['CS Vec spare and interner allocation', 'ValueVec and UE semantic data',
                 'outer wrapper', 'retained BufferPool blocks', 'later oracles and FRI opening',
                 'allocator metadata and runtime'],
        full_proof_body_bytes=None, full_Prove_seconds=None, full_Verify_seconds=None,
        full_measured_RSS_bytes=None)
