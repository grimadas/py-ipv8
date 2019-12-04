from ...community import Community


class TrustPeer(object):
    def __init__(self, mid):
        self.mid = mid


class GossipCommunity(Community):
    """
    Gossip community around a specific peer.
    """

    def __init__(self, *args, **kwargs):
        self.master_peer = TrustPeer(kwargs.pop('mid'))
        self._prefix = b'\x00' + self.version + self.master_peer.mid
        super(GossipCommunity, self).__init__(*args, **kwargs)
