# PQ-RBBC system package

New system-level implementation is organized by protocol responsibility:

- `contracts/`: byte-level ABIs shared across modules;
- `governance/`: system initialization and authorization;
- `opening/`: conditional-opening request, gate, shares, and combiner;
- `access/`: future satellite access and AKE state machines;
- `handover/`: future handover and continuous-authentication state machines.

The existing flat `src/pq_rbbc_*.py` cryptographic-core files are not moved
while frozen commands, evidence identities, and active CAP work depend on
their paths.  A later migration must preserve compatibility and be handled as
its own verified checkpoint.
