import csv
import logging
import time
from binascii import hexlify
from hashlib import sha1

from ipv8.attestation.backbone.block import NoodleBlock, EMPTY_PK
from ipv8.attestation.backbone.datastore.consistency import Chain
from ipv8.attestation.backbone.datastore.utils import key_to_id, expand_ranges


class NoodleMemoryDatabase(object):
    """
    This class defines an optimized memory database for Noodle.
    """

    def __init__(self, working_directory, db_name, original_db=None, accept_all_chains=True):
        self.working_directory = working_directory
        self.db_name = db_name

        self.identity_chains = dict()
        self.community_chains = dict()

        self.blocks = {}
        self.block_cache = {}

        self.block_types = {}
        self.latest_blocks = {}

        self.short_map = dict()

        self.logger = logging.getLogger(self.__class__.__name__)

        self.peer_map = {}
        self.do_commit = True

        self.block_time = {}
        self.block_file = None

        # Will reconcile and track all chains received from blocks and frontiers
        self.should_accept_all_chains = accept_all_chains

        self.original_db = None
        if original_db:
            self.original_db = original_db

            # Fill the memory database with the blocks in the original database
            blocks = original_db.get_all_blocks()
            self.logger.info("Filling memory DB with %d blocks..." % len(blocks))
            for block in blocks:
                self.add_block(block)
                peer_mid = sha1(block.public_key).digest()
                self.peer_map[peer_mid] = block.public_key

    def get_frontier(self, chain_id):
        val = self.get_peer_frontier(chain_id)
        return val if val else self.get_community_frontier(chain_id)

    def get_peer_proofs(self, chain, blk_hash, state):
        pass

    def is_state_consistent(self, chain_id):
        if chain_id not in self.community_chains and chain_id not in self.identity_chains:
            return None
        return self.community_chains[chain_id].is_state_consistent() if chain_id in self.community_chains \
            else self.identity_chains[chain_id].is_state_consistent()

    def get_latest_state(self, chain_id, state_name=None):
        if chain_id not in self.community_chains and chain_id not in self.identity_chains:
            return None
        states = self.community_chains[chain_id].states if chain_id in self.community_chains \
            else self.identity_chains[chain_id].states
        if state_name:
            return states.get(state_name)
        else:
            return states

    def get_chain(self, com_id):
        if com_id not in self.community_chains and com_id not in self.identity_chains:
            return None
        return self.community_chains[com_id] if com_id in self.community_chains else self.identity_chains[com_id]

    def get_community_frontier(self, com_id):
        if com_id in self.community_chains:
            return self.community_chains[com_id].frontier
        return None

    def get_peer_frontier(self, peer_id):
        if peer_id in self.identity_chains:
            return self.identity_chains[peer_id].frontier
        return None

    def reconcile_or_create_personal_chain(self, peer_id, frontier):
        if peer_id not in self.identity_chains:
            self.identity_chains[peer_id] = Chain(peer_id)
        return self.reconcile(peer_id, frontier)

    def reconcile_or_create_community_chain(self, com_id, frontier):
        if com_id not in self.community_chains:
            self.community_chains[com_id] = Chain(com_id, personal=False)
        return self.reconcile(com_id, frontier)

    def reconcile_or_create(self, chain_id, frontier):
        if 'p' in frontier and frontier['p']:
            return self.reconcile_or_create_personal_chain(chain_id, frontier)
        else:
            return self.reconcile_or_create_community_chain(chain_id, frontier)

    def reconcile(self, chain_id, frontier):
        if chain_id in self.community_chains:
            return self.community_chains[chain_id].reconcile(frontier)
        elif chain_id in self.identity_chains:
            return self.identity_chains[chain_id].reconcile(frontier)
        return None

    def get_block_by_short_hash(self, short_hash):
        full_hash = self.short_map.get(short_hash)
        return self.blocks.get(full_hash)

    def get_blocks_by_request(self, chain_id, request):
        blocks = set()
        chain = self.identity_chains[chain_id] if chain_id in self.identity_chains else self.community_chains[chain_id]
        for b_i in expand_ranges(request['m']):
            # FIXME will definitely fail
            blocks.update({self.get_block_by_short_hash(sh) for sh in chain.chain[b_i]})
        for sn, sh in request['c']:
            blocks.add(self.get_block_by_short_hash(sh))
        return blocks

    def get_block_class(self, block_type):
        """
        Get the block class for a specific block type.
        """
        if block_type not in self.block_types:
            return NoodleBlock

        return self.block_types[block_type]

    def add_peer(self, peer):
        if peer.mid not in self.peer_map:
            self.peer_map[peer.mid] = peer.public_key.key_to_bin()

    def add_block(self, block: NoodleBlock):
        """
        Add block to the database and update indexes
        @param block: NoodleBlock
        """
        if block.hash not in self.blocks:
            self.blocks[block.hash] = block
            self.short_map[key_to_id(block.hash)] = block.hash

        if block.public_key not in self.block_cache:
            # This is a public key => new user
            self.block_cache[block.public_key] = dict()

            self.short_map[key_to_id(block.public_key)] = block.public_key
            # Initialize identity chain
            self.identity_chains[block.public_key] = Chain(block.public_key)
        block_id = block.sequence_number
        if block_id not in self.block_cache[block.public_key]:
            self.block_cache[block.public_key][block_id] = set()
        self.block_cache[block.public_key][block_id].add(block.hash)

        self.identity_chains[block.public_key].add_block(block)

        # Add to community chain
        if block.com_id != EMPTY_PK:
            if block.com_id not in self.community_chains:
                self.community_chains[block.com_id] = Chain(block.com_id, personal=False)
            self.community_chains[block.com_id].add_block(block)

        # time when block is received by peer
        self.block_time[block.hash] = int(round(time.time() * 1000))

        # add to persistent
        # if self.original_db and self.do_commit:
        #    self.original_db.add_block(block)

    def remove_block(self, block):
        self.block_cache.pop((block.public_key, block.sequence_number), None)

    def get(self, public_key, sequence_number):
        if public_key in self.block_cache and sequence_number in self.block_cache[public_key]:
            return self.block_cache[public_key][sequence_number]
        return None

    def get_all_blocks(self):
        return self.blocks.values()

    def get_number_of_known_blocks(self, public_key=None):
        if public_key:
            return len([pk for pk, _ in self.block_cache.keys() if pk == public_key])
        return len(self.block_cache.keys())

    def contains(self, block):
        return block.hash in self.blocks

    def get_lastest_peer_frontier(self, peer_key):
        if peer_key in self.identity_chains:
            return self.identity_chains[peer_key].frontier
        return None

    def get_latest_community_frontier(self, com_key):
        if com_key in self.community_chains:
            return self.community_chains[com_key].frontier
        return None

    def commit_block_times(self):

        if self.block_file:
            with open(self.block_file, "a") as t_file:
                writer = csv.DictWriter(t_file, ['time', 'transaction', 'type',
                                                 'peer_id', "seq_num",
                                                 'com_id', 'com_seq', "links", 'prevs'])
                block_ids = list(self.block_time.keys())
                for block_id in block_ids:
                    block = self.blocks[block_id]
                    time = self.block_time[block_id]
                    from_id = hexlify(block.public_key).decode()[-8:]
                    com_id = hexlify(block.com_id).decode()[-8:]

                    writer.writerow({"time": time, 'transaction': str(block.transaction),
                                     'type': block.type.decode(),
                                     'seq_num': block.sequence_number,
                                     'peer_id': from_id,
                                     'com_id': com_id,
                                     "com_seq": block.com_seq_num,
                                     'links': str(block.links),
                                     'prevs': str(block.previous)})
                    self.block_time.pop(block_id)

    def commit(self, my_pub_key):
        """
        Commit all information to the original database.
        """
        if self.original_db:
            my_blocks = [self.blocks[b_hashes] for b_hashes in self.block_cache[my_pub_key].values()]
            for block in my_blocks:
                self.original_db.add_block(block)

    def close(self):
        if self.original_db:
            self.original_db.close()