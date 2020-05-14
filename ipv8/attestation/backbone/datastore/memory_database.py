import csv
import logging
import os
import time
from binascii import hexlify
from hashlib import sha1

from six.moves import xrange

from ipv8.attestation.backbone.block import NoodleBlock, GENESIS_HASH, GENESIS_SEQ
from ipv8.attestation.backbone.datastore.consistency import Chain
from ipv8.attestation.backbone.datastore.utils import key_to_id


class NoodleMemoryDatabase(object):
    """
    This class defines an optimized memory database for Noodle.
    """

    def __init__(self, working_directory, db_name, original_db=None):
        self.working_directory = working_directory
        self.db_name = db_name

        self.identity_chains = dict()
        self.community_chains = dict()

        self.block_cache = {}
        self.linked_block_cache = {}

        self.block_types = {}
        self.latest_blocks = {}

        self.short_map = dict()

        self.logger = logging.getLogger(self.__class__.__name__)

        self.double_spends = {}
        self.peer_map = {}
        self.do_commit = True

        # TODO: remove graph from the noodle database
        self.graph_path = os.path.join(self.working_directory, "work_graph.pickle")
        if os.path.exists(self.graph_path):
            self.work_graph = nx.read_gpickle(self.graph_path)
        else:
            self.work_graph = nx.DiGraph()
        self.known_connections = nx.Graph()

        self.claim_proofs = {}
        self.nonces = {}

        self.block_time = {}
        self.block_file = None

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

    def get_latest_peer_block_by_mid(self, peer_mid):
        if peer_mid in self.peer_map:
            pub_key = self.peer_map[peer_mid]
            return self.get_latest(pub_key)

    def add_connections(self, peer_a, peer_b):
        self.known_connections.add_edge(peer_a, peer_b)

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

    def get_latest_peer_block_by_mid(self, peer_mid):
        if peer_mid in self.peer_map:
            pub_key = self.peer_map[peer_mid]
            return self.get_latest(pub_key)

    def add_block(self, block: NoodleBlock):
        """
        Add block to the database and update indexes
        @param block: NoodleBlock
        """
        if block.public_key not in self.block_cache:
            # This is a public key => new user
            self.block_cache[block.public_key] = dict()
            self.block_time[block.public_key] = dict()

            self.short_map[key_to_id(block.public_key)] = block.public_key

            # Initialize identity chain
            self.identity_chains[block.public_key] = Chain()
        block_id = block.sequence_number
        if block_id not in self.block_cache[block.public_key]:
            self.block_cache[block.public_key][block_id] = {block.hash: block}
        if key_to_id(block.hash) not in self.short_map:
            self.short_map[key_to_id(block.hash)] = block.hash

        self.linked_block_cache[(block.link_public_key, block.link_sequence_number)] = block

        # time when block is received by peer
        self.block_time[block.public_key][block_id] = int(round(time.time() * 1000))

        # add to persistent
        # if self.original_db and self.do_commit:
        #    self.original_db.add_block(block)

    def get_new_peer_nonce(self, peer_pk):
        peer_id = key_to_id(peer_pk)
        if peer_id not in self.nonces:
            self.nonces[peer_id] = '1'
        else:
            self.nonces[peer_id] = str(int(self.nonces[peer_id]) + 1)
        return self.nonces[peer_id]

    def add_peer_proofs(self, peer_id, seq_num, status, proofs):
        if peer_id not in self.claim_proofs or self.claim_proofs[peer_id][0] < seq_num:
            self.claim_proofs[peer_id] = (seq_num, status, proofs)

    def get_peer_proofs(self, peer_id, seq_num):
        if peer_id not in self.claim_proofs or seq_num > self.claim_proofs[peer_id][0]:
            return None
        return self.claim_proofs[peer_id]

    def get_last_seq_num(self, peer_id):
        if peer_id not in self.claim_proofs:
            return 0
        else:
            return self.claim_proofs[peer_id][0]

    def dump_peer_status(self, peer_id, status):
        if 'spends' not in status or 'claims' not in status:
            # Status is ill-formed
            return False

        for (p, (val, seq_num)) in status['spends'].items():
            self.update_spend(peer_id, p, float(val), int(seq_num))

        for (p, (val, seq_num)) in status['claims'].items():
            self.update_claim(p, peer_id, float(val), int(seq_num))

        return True

    def get_balance(self, peer_id, verified=True):
        # Sum of claims(verified/or not) - Sum of spends(all known)
        return self.get_total_claims(peer_id, only_verified=verified) - self.get_total_spends(peer_id)

    def remove_block(self, block):
        self.block_cache.pop((block.public_key, block.sequence_number), None)
        self.linked_block_cache.pop((block.link_public_key, block.link_sequence_number), None)

    def get(self, public_key, sequence_number):
        if public_key in self.block_time:
            return self.block_cache[public_key][sequence_number]
        return None

    def get_all_blocks(self):
        return self.block_cache.values()

    def get_number_of_known_blocks(self, public_key=None):
        if public_key:
            return len([pk for pk, _ in self.block_cache.keys() if pk == public_key])
        return len(self.block_cache.keys())

    def contains(self, block):
        return block.public_key in self.block_cache and block.sequence_number in self.block_cache[block.public_key] and \
               block.hash in self.block_cache[block.public_key][block.sequence_number]

    def get_lastest_peer_frontier(self, peer_key):
        if peer_key in self.identity_chains:
            return self.identity_chains[peer_key].frontier
        return None

    def get_latest_community_frontier(self, com_key):
        if com_key in self.community_chains:
            return self.community_chains[com_key].frontier
        return None

    def get_latest_blocks(self, public_key, limit=25, block_types=None):
        latest_block = self.get_latest(public_key)
        if not latest_block:
            return []  # We have no latest blocks

        blocks = [latest_block]
        cur_seq = latest_block.sequence_number - 1
        while cur_seq > 0:
            cur_block = self.get(public_key, cur_seq)
            if cur_block and (not block_types or cur_block.type in block_types):
                blocks.append(cur_block)
                if len(blocks) >= limit:
                    return blocks
            cur_seq -= 1

        return blocks

    def get_block_after(self, block, block_type=None):
        # TODO for now we assume block_type is None
        if (block.public_key, block.sequence_number + 1) in self.block_cache:
            return self.block_cache[(block.public_key, block.sequence_number + 1)]
        return None

    def get_block_before(self, block, block_type=None):
        # TODO for now we assume block_type is None
        if (block.public_key, block.sequence_number - 1) in self.block_cache:
            return self.block_cache[(block.public_key, block.sequence_number - 1)]
        return None

    def get_lowest_sequence_number_unknown(self, public_key):
        if public_key not in self.latest_blocks:
            return 1
        latest_seq_num = self.latest_blocks[public_key].sequence_number
        for ind in xrange(1, latest_seq_num + 2):
            if (public_key, ind) not in self.block_cache:
                return ind

    def get_lowest_range_unknown(self, public_key):
        lowest_unknown = self.get_lowest_sequence_number_unknown(public_key)
        known_block_nums = [seq_num for pk, seq_num in self.block_cache.keys() if pk == public_key]
        filtered_block_nums = [seq_num for seq_num in known_block_nums if seq_num > lowest_unknown]
        if filtered_block_nums:
            return lowest_unknown, filtered_block_nums[0] - 1
        else:
            return lowest_unknown, lowest_unknown

    def get_linked(self, block):
        if (block.link_public_key, block.link_sequence_number) in self.block_cache:
            return self.block_cache[(block.link_public_key, block.link_sequence_number)]
        if (block.public_key, block.sequence_number) in self.linked_block_cache:
            return self.linked_block_cache[(block.public_key, block.sequence_number)]
        return None

    def crawl(self, public_key, start_seq_num, end_seq_num, limit=100):
        # TODO we assume only ourselves are crawled
        blocks = []
        orig_blocks_added = 0
        for seq_num in xrange(start_seq_num, end_seq_num + 1):
            if (public_key, seq_num) in self.block_cache:
                block = self.block_cache[(public_key, seq_num)]
                blocks.append(block)
                orig_blocks_added += 1
                linked_block = self.get_linked(block)
                if linked_block:
                    blocks.append(linked_block)

            if orig_blocks_added >= limit:
                break

        return blocks

    def commit_block_times(self):
        self.write_work_graph()

        if self.block_file:
            with open(self.block_file, "a") as t_file:
                writer = csv.DictWriter(t_file, ['time', 'transaction', 'type', "seq_num", "link", 'from_id', 'to_id'])
                block_ids = list(self.block_time.keys())
                for block_id in block_ids:
                    block = self.block_cache[block_id]
                    time = self.block_time[block_id]
                    from_id = hexlify(block.public_key).decode()[-8:]
                    to_id = hexlify(block.link_public_key).decode()[-8:]
                    writer.writerow({"time": time, 'transaction': str(block.transaction),
                                     'type': block.type.decode(),
                                     'seq_num': block.sequence_number, "link": block.link_sequence_number,
                                     'from_id': from_id, 'to_id': to_id
                                     })
                    self.block_time.pop(block_id)

    def commit(self, my_pub_key):
        """
        Commit all information to the original database.
        """
        if self.original_db:
            my_blocks = [block for block in self.block_cache.values() if block.public_key == my_pub_key]
            for block in my_blocks:
                self.original_db.add_block(block)

    def write_work_graph(self):
        if not self.working_directory or os.path.exists(self.working_directory):
            nx.write_gpickle(self.work_graph, self.graph_path)

    def close(self):
        self.write_work_graph()

        if self.original_db:
            self.original_db.close()
