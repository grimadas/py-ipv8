from ..trustchain.community import TrustChainCommunity


class NoodleCommunity(TrustChainCommunity):
    """
    The Noodle community.
    """

    def __init__(self, *args, **kwargs):
        self.ipv8 = kwargs.pop('ipv8', None)
        super(NoodleCommunity, self).__init__(*args, **kwargs)

        self.known_graph = None
        self.periodic_sync_lc = {}
        self.mem_db_flush_lc = None
        self.pex = {}
        self.pex_map = {}
        self.bootstrap_master = None
        self.audit_requests = {}
        self.minters = set()
