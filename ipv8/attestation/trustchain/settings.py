from enum import Enum


class SecurityMode(Enum):
    """
    Implementations of security implementations of Trustchain
    """
    VANILLA = 1
    ACTIVE = 2
    PASSIVE = 3


class TrustChainSettings(object):
    """
    This class holds various settings regarding TrustChain.
    """

    def __init__(self):
        # The set with block types that should not be broadcast
        self.block_types_bc_disabled = set()

        # The fan-out of the broadcast when a new block is created
        self.broadcast_fanout = 25

        # How many prior blocks we require before signing a new incoming block
        self.validation_range = 5

        # The maximum number of blocks we want to store in the database
        self.max_db_blocks = 1000000

        # Whether we are a crawler (and fetching whole chains)
        self.crawler = False

        # Is the node hiding own blocks?
        self.is_hiding = False

        # TTL for informed information dissemination, depends on the topology
        self.ttl = 3

        # Use informed broadcast
        self.use_informed_broadcast = False

        # Ignore validation errors
        self.ignore_validation = False

        # Id of the peer
        self.my_id = 1

        # Sub-community introduction time in seconds 
        self.intro_run = 100

        # Sync round time in seconds 
        self.sync_time = 1

        # Security mode
        self.security_mode = SecurityMode.VANILLA
