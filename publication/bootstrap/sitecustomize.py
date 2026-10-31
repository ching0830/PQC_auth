"""Role subprocess startup for the explicit publication command only."""
import os
import sys

if 'PQSAT_PUBLICATION_CONFIG' in os.environ:
    try:
        from publication.runtime import activate
        activate(os.environ['PQSAT_PUBLICATION_CONFIG'])
    except Exception:
        # Python otherwise ignores sitecustomize failures. Refuse role startup.
        print('PQSAT_PUBLICATION_CONFIGURATION_REJECTED', file=sys.stderr, flush=True)
        os._exit(78)
