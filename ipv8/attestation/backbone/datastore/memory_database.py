import csv
import logging
import os
import time
from binascii import hexlify
from hashlib import sha1

from six.moves import xrange

from ipv8.attestation.backbone.block import NoodleBlock, GENESIS_HASH, GENESIS_SEQ, EMPTY_PK
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

        self.peer_map = {}
        self.do_commit = True

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
                
    def get_frontier(self, chain_id):
        val = self.get_peer_frontier(chain_id)
        return val if val else self.get_community_frontier(chain_id)

    def get_community_frontier(self, com_id):
        if com_id in self.community_chains:
            return self.community_chains[com_id].frontier
        return None
 
    def get_peer_frontier(self, peer_id):
        if peer_id in self.identity_chains:
            return self.identity_chains[peer_id].frontier
        return None

    def get_blocks_by_links(self, links):
        pass
        #for s,h in links:


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
        self.identity_chains[block.public_key].add_block(block)

        # Add to community chain
        if block.com_id != EMPTY_PK:
            if block.com_id not in self.community_chains:
                self.community_chains[block.com_id] = Chain(personal=False)
            self.community_chains[block.com_id].add_block(block)

        # time when block is received by peer
        self.block_time[block.public_key][block_id] = int(round(time.time() * 1000))

        # add to persistent
        # if self.original_db and self.do_commit:
        #    self.original_db.add_block(block)

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
