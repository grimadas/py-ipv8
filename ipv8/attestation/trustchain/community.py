"""
The TrustChain Community is the first step in an incremental approach in building a new reputation system.
This reputation system builds a tamper proof interaction history contained in a chain data-structure.
Every node has a chain and these chains intertwine by blocks shared by chains.
"""
from __future__ import absolute_import

import csv
import logging
import orjson
import os
import random
import struct
import time
from binascii import hexlify, unhexlify
from functools import wraps
from threading import RLock

import networkx as nx
from twisted.internet import reactor
from twisted.internet.defer import Deferred, fail, inlineCallbacks, maybeDeferred, returnValue, succeed
from twisted.internet.task import LoopingCall

from ipv8.peerdiscovery.discovery import RandomWalk
from ipv8.peerdiscovery.network import Network
from .block import ANY_COUNTERPARTY_PK, EMPTY_PK, GENESIS_SEQ, TrustChainBlock, UNKNOWN_SEQ, ValidationResult
from .caches import ChainCrawlCache, CrawlRequestCache, HalfBlockSignCache, IntroCrawlTimeout
from .database import TrustChainDB
from .payload import *
from ...attestation.trustchain.settings import TrustChainSettings
from ...community import Community
from ...lazy_community import lazy_wrapper, lazy_wrapper_unsigned, lazy_wrapper_unsigned_wd
from ...messaging.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from ...peer import Peer
from ...requestcache import RandomNumberCache, RequestCache
from ...util import addCallback


def synchronized(f):
    """
    Due to database inconsistencies, we can't allow multiple threads to handle a received_half_block at the same time.
    """

    @wraps(f)
    def wrapper(self, *args, **kwargs):
        with self.receive_block_lock:
            return f(self, *args, **kwargs)

    return wrapper


class TrustPeer(object):
    def __init__(self, mid):
        self.mid = mid


class SubTrustCommunity(Community):

    def __init__(self, *args, **kwargs):
        self.master_peer = TrustPeer(kwargs.pop('mid'))
        self._prefix = b'\x00' + self.version + self.master_peer.mid
        super(SubTrustCommunity, self).__init__(*args, **kwargs)


class TrustChainCommunity(Community):
    """
    Community for reputation based on TrustChain tamper proof interaction history.
    """
    master_peer = Peer(unhexlify("4c69624e61434c504b3a5730f52156615ecbcedb36c442992ea8d3c26b418edd8bd00e01dce26028cd"
                                 "1ebe5f7dce59f4ed59f8fcee268fd7f1c6dc2fa2af8c22e3170e00cdecca487745"))

    UNIVERSAL_BLOCK_LISTENER = b'UNIVERSAL_BLOCK_LISTENER'
    DB_CLASS = TrustChainDB
    DB_NAME = 'trustchain'
    version = b'\x02'

    def __init__(self, *args, **kwargs):
        working_directory = kwargs.pop('working_directory', '')
        db_name = kwargs.pop('db_name', self.DB_NAME)
        self.settings = kwargs.pop('settings', TrustChainSettings())
        self.receive_block_lock = RLock()
        super(TrustChainCommunity, self).__init__(*args, **kwargs)
        self.request_cache = RequestCache()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.persistence = self.DB_CLASS(working_directory, db_name, self.my_peer.public_key.key_to_bin())
        self.relayed_broadcasts = []
        self.logger.debug("The trustchain community started with Public Key: %s",
                          hexlify(self.my_peer.public_key.key_to_bin()))
        self.shutting_down = False
        self.listeners_map = {}  # Map of block_type -> [callbacks]
        self.db_cleanup_lc = self.register_task("db_cleanup", LoopingCall(self.do_db_cleanup))
        self.db_cleanup_lc.start(600)
        self.known_graph = None
        self.periodic_sync_lc = {}

        # Trustchain SubCommunities
        self.ipv8 = kwargs.pop('ipv8', None)
        self.pex = {}
        self.pex_map = {}
        self.bootstrap_master = None

        self.decode_map.update({
            chr(1): self.received_half_block,
            chr(2): self.received_crawl_request,
            chr(3): self.received_crawl_response,
            chr(4): self.received_half_block_pair,
            chr(5): self.received_half_block_broadcast,
            chr(6): self.received_half_block_pair_broadcast,
            chr(7): self.received_empty_crawl_response,
            chr(8): self.received_peer_crawl_request,
            chr(9): self.received_peer_crawl_response,
        })

    def trustchain_sync(self, peer_mid):
        self.logger.info("Sync for the info peer  %s", peer_mid)
        blk = self.persistence.get_latest_peer_block(peer_mid)
        val = self.ipv8.overlays[self.pex_map[peer_mid]].get_peers()
        if blk:
            self.send_block(blk, address_set=val)
        # Send also the last pairwise block to the peers
        if peer_mid in self.persistence.peer_map:
            blk = self.persistence.get_last_pairwise_block(self.persistence.peer_map[peer_mid],
                                                           self.my_peer.public_key.key_to_bin())
            if blk:
                self.send_block_pair(blk[0], blk[1], address_set=val)

    def get_hop_to_peer(self, peer_pub_key):
        """
        Get next hop to peer
        :param peer_pub_key: public key of the destination
        :return: the next hop for the peer
        """
        p = self.get_peer_by_pub_key(peer_pub_key)
        if p:
            # Directly connected
            return p
        # Look in the known_graph the path to the peer
        if not self.known_graph:
            self.logger.error("World graph is not known")
        else:
            path = nx.shortest_path(self.known_graph, source=self.my_peer.public_key.key_to_bin(), target=peer_pub_key)
            p = self.get_peer_by_pub_key(path[1])
            return p

        # for peer_mid, sub_com in self.pex.items():
        #    p = sub_com.get_peer_by_pub_key(peer_pub_key)
        #    if p:
        #        # Connected through peer_mid
        #        return self.get_peer_by_mid(peer_mid)
        # Peer not found => choose randomly??
        # return random.choice(list(self.get_peers()))

    def prepare_spend_transaction(self, pub_key, spend_value, **kwargs):
        # check the balance first
        my_pk = self.my_peer.public_key.key_to_bin()
        my_id = self.persistence.key_to_id(my_pk)
        my_balance = self.persistence.get_balance(my_id)

        if my_balance < spend_value:
            return None
        else:
            peer = self.get_hop_to_peer(pub_key)
            peer_id = self.persistence.key_to_id(peer.public_key.key_to_bin())
            pw_total = self.persistence.get_total_pairwise_spends(my_id, peer_id)
            added = {"value": spend_value, "total_spend": pw_total + spend_value}
            added.update(**kwargs)
            return peer, added

    def prepare_mint_transaction(self):
        # TODO: replace with settings
        mint_val = 1000
        if os.getenv('INIT_MINT'):
            mint_val = float(os.getenv('INIT_MINT'))

        minter = self.persistence.key_to_id(EMPTY_PK)
        pk = self.my_peer.public_key.key_to_bin()
        my_id = self.persistence.key_to_id(pk)
        total = self.persistence.get_total_pairwise_spends(minter, my_id)
        transaction = {"value": mint_val, "mint_proof": True, "total_spend": total + mint_val}
        return transaction

    def do_db_cleanup(self):
        """
        Cleanup the database if necessary.
        """
        blocks_in_db = self.persistence.get_number_of_known_blocks()
        if blocks_in_db > self.settings.max_db_blocks:
            my_pk = self.my_peer.public_key.key_to_bin()
            self.persistence.remove_old_blocks(blocks_in_db - self.settings.max_db_blocks, my_pk)

    def add_listener(self, listener, block_types):
        """
        Add a listener for specific block types.
        """
        for block_type in block_types:
            if block_type not in self.listeners_map:
                self.listeners_map[block_type] = []
            self.listeners_map[block_type].append(listener)
            self.persistence.block_types[block_type] = listener.BLOCK_CLASS

    def remove_listener(self, listener, block_types):
        for block_type in block_types:
            if block_type in self.listeners_map and listener in self.listeners_map[block_type]:
                self.listeners_map[block_type].remove(listener)
            if block_type in self.persistence.block_types:
                self.persistence.block_types.pop(block_type, None)

    def get_block_class(self, block_type):
        """
        Get the block class for a specific block type.
        """
        if block_type not in self.listeners_map or not self.listeners_map[block_type]:
            return TrustChainBlock

        return self.listeners_map[block_type][0].BLOCK_CLASS

    @inlineCallbacks
    def should_sign(self, block):
        """
        Return whether we should sign the block in the passed message.
        @param block: the block we want to sign or not.
        """
        if block.type not in self.listeners_map:
            returnValue(False)  # There are no listeners for this block

        for listener in self.listeners_map[block.type]:
            should_sign = yield maybeDeferred(listener.should_sign, block)
            if should_sign:
                returnValue(True)

        returnValue(False)

    def informed_send_block(self, block1, block2=None, ttl=None, fanout=None):
        """
        Spread block among your verified peers.
        """
        global_time = self.claim_global_time()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()
        if block2:
            if block1.link_sequence_number == UNKNOWN_SEQ:
                block = block1
            else:
                block = block2
        else:
            block = block1
        # Get information about the block counterparties
        if not ttl:
            ttl = self.settings.ttl
        know_neigh = self.network.known_network.get_neighbours(block.public_key)
        if not know_neigh:
            # No neighbours known, spread randomly
            if block2:
                self.send_block_pair(block1, block2, ttl=ttl)
            else:
                self.send_block(block1, ttl=ttl)
        else:
            next_peers = set()
            for neigh in know_neigh:
                paths = self.network.known_network.get_path_to_peer(self.my_peer.public_key.key_to_bin(), neigh,
                                                                    cutoff=ttl + 1)
                for p in paths:
                    next_peers.add(p[1])
            res_fanout = fanout if fanout else self.settings.broadcast_fanout
            if len(next_peers) < res_fanout:
                # There is not enough information to build paths - choose at random
                for peer in random.sample(self.get_peers(), min(len(self.get_peers()),
                                                                res_fanout)):
                    next_peers.add(peer.public_key.key_to_bin())
            if len(next_peers) > res_fanout:
                next_peers = random.sample(list(next_peers), res_fanout)

            if block2:
                payload = HalfBlockPairBroadcastPayload.from_half_blocks(block1, block2, ttl).to_pack_list()
                packet = self._ez_pack(self._prefix, 6, [dist, payload], False)
            else:
                payload = HalfBlockBroadcastPayload.from_half_block(block, ttl).to_pack_list()
                packet = self._ez_pack(self._prefix, 5, [dist, payload], False)

            for peer_key in next_peers:
                peer = self.network.get_verified_by_public_key_bin(peer_key)
                self.logger.debug("Sending block to %s", peer)
                p = peer.address
                self.register_anonymous_task("informed_send_block",
                                             reactor.callLater(random.random() * 0.1,
                                                               self.endpoint.send, p, packet))

            self.relayed_broadcasts.append(block.block_id)

    def send_block(self, block, address=None, address_set=None, ttl=1):
        """
        Send a block to a specific address, or do a broadcast to known peers if no peer is specified.
        """
        if ttl < 1:
            return
        global_time = self.claim_global_time()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        if address:
            self.logger.debug("Sending block to (%s:%d) (%s)", address[0], address[1], block)
            payload = HalfBlockPayload.from_half_block(block).to_pack_list()
            packet = self._ez_pack(self._prefix, 1, [dist, payload], False)
            self.endpoint.send(address, packet)
        else:
            payload = HalfBlockBroadcastPayload.from_half_block(block, ttl).to_pack_list()
            packet = self._ez_pack(self._prefix, 5, [dist, payload], False)

            if address_set:
                f = min(len(address_set), self.settings.broadcast_fanout)
                self.logger.debug("Broadcasting block in a back-channel  to %s peers", f)
                peers = (p.address for p in random.sample(address_set, f))
            else:
                f = min(len(self.get_peers()), self.settings.broadcast_fanout)
                self.logger.debug("Broadcasting block in a main-channel  to %s peers", f)
                peers = (p.address for p in random.sample(self.get_peers(), f))

            peers = (p.address for p in random.sample(self.get_peers(), f))
            for p in peers:
                self.endpoint.send(p, packet)
                # self.register_anonymous_task("send_block",
                #                             reactor.callLater(random.random() * 0.2, self.endpoint.send, p, packet))

            self.relayed_broadcasts.append(block.block_id)

    def send_block_pair(self, block1, block2, address=None, address_set=None, ttl=1):
        """
        Send a half block pair to a specific address, or do a broadcast to known peers if no peer is specified.
        """
        global_time = self.claim_global_time()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        if address:
            self.logger.info("Sending block pair to (%s:%d) (%s and %s)", address[0], address[1], block1, block2)
            payload = HalfBlockPairPayload.from_half_blocks(block1, block2).to_pack_list()
            packet = self._ez_pack(self._prefix, 4, [dist, payload], False)
            self.endpoint.send(address, packet)
        else:

            payload = HalfBlockPairBroadcastPayload.from_half_blocks(block1, block2, ttl).to_pack_list()
            packet = self._ez_pack(self._prefix, 6, [dist, payload], False)
            if address_set:
                f = min(len(address_set), self.settings.broadcast_fanout)
                self.logger.debug("Broadcasting block pair in a back-channel  to %s peers", f)
                peers = (p.address for p in random.sample(address_set, f))
            else:
                f = min(len(self.get_peers()), self.settings.broadcast_fanout)
                self.logger.debug("Broadcasting block pair in a main-channel  to %s peers", f)
                peers = (p.address for p in random.sample(self.get_peers(), f))

            for p in peers:
                self.endpoint.send(p, packet)
                # self.register_anonymous_task("send_block_pair",
                #                             reactor.callLater(random.random() * 0.2, self.endpoint.send, p, packet))
            self.relayed_broadcasts.append(block1.block_id)

    def self_sign_block(self, block_type=b'unknown', transaction=None):
        self.sign_block(self.my_peer, block_type=block_type, transaction=transaction)

    def create_source_block(self, block_type=b'unknown', transaction=None):
        """
        Create a source block without any initial counterparty to sign.

        :param block_type: The type of the block to be constructed, as a string
        :param transaction: A string describing the interaction in this block
        :return: A deferred that fires with a (block, None) tuple
        """
        return self.sign_block(peer=None, public_key=ANY_COUNTERPARTY_PK,
                               block_type=block_type, transaction=transaction)

    def create_link(self, source, block_type, additional_info=None, public_key=None):
        """
        Create a Link Block to a source block

        :param source: The source block which had no initial counterpary to sign
        :param block_type: The type of the block to be constructed, as a string
        :param additional_info: a dictionary with supplementary information concerning the transaction
        :param public_key: The public key of the counterparty (usually of the source's owner)
        :return: None
        """
        public_key = source.public_key if public_key is None else public_key

        return self.sign_block(self.my_peer, linked=source, public_key=public_key, block_type=block_type,
                               additional_info=additional_info)

    def sign_block(self, peer, public_key=EMPTY_PK, block_type=b'unknown', transaction=None, linked=None,
                   additional_info=None, double_spend_block=None, from_peer=None, from_peer_seq_num=None):
        """
        Create, sign, persist and send a block signed message
        :param peer: The peer with whom you have interacted, as a IPv8 peer
        :param public_key: The public key of the other party you transact with
        :param block_type: The type of the block to be constructed, as a string
        :param transaction: A string describing the interaction in this block
        :param linked: The block that the requester is asking us to sign
        :param additional_info: Stores additional information, on the transaction
        :param double_spend_block: Number of block if you want to double sign
        :param from_peer:  Optional parameter for conditional chain payments
        :param from_peer_seq_num: Optional parameter for conditional chain payments
        """
        # NOTE to the future: This method reads from the database, increments and then writes back. If in some future
        # this method is allowed to execute in parallel, be sure to lock from before .create up to after .add_block

        # In this particular case there must be an implicit transaction due to the following assert
        assert peer is not None or peer is None and linked is None and public_key == ANY_COUNTERPARTY_PK, \
            "Peer, linked block should not be provided when creating a no counterparty source block. Public key " \
            "should be that reserved for any counterpary."
        assert transaction is None and linked is not None or transaction is not None and linked is None, \
            "Either provide a linked block or a transaction, not both %s, %s" % (peer, self.my_peer)
        assert (additional_info is None or linked is not None
                and transaction is None), \
            "Either no additional info is provided or one provides it for a linked block"
        assert (linked is None or linked.link_public_key == self.my_peer.public_key.key_to_bin()
                or linked.link_public_key == ANY_COUNTERPARTY_PK), "Cannot counter sign block not addressed to self"
        assert linked is None or linked.link_sequence_number == UNKNOWN_SEQ, \
            "Cannot counter sign block that is not a request"
        assert transaction is None or isinstance(transaction, dict), "Transaction should be a dictionary"
        assert additional_info is None or isinstance(additional_info, dict), "Additional info should be a dictionary"

        # self.persistence_integrity_check()

        # if linked and linked.link_public_key != ANY_COUNTERPARTY_PK:
        #    block_type = linked.type
        if linked:
            self.logger.info("Sign the linked block for the claim %s, creating a block with type %s", linked,
                             block_type)

        block = self.get_block_class(block_type).create(block_type, transaction, self.persistence,
                                                        self.my_peer.public_key.key_to_bin(),
                                                        link=linked, additional_info=additional_info,
                                                        link_pk=public_key, double_spend_seq=double_spend_block)
        block.sign(self.my_peer.key)

        # validation = block.validate(self.persistence)
        '''
        self.logger.info("Signed block to %s (%s) validation result %s",
                         hexlify(block.link_public_key)[-8:], block, validation)
        if not self.settings.ignore_validation and validation[0] != ValidationResult.partial_next \
                and validation[0] != ValidationResult.valid:
            self.logger.error("Signed block did not validate?! Result %s", repr(validation))
            return fail(RuntimeError("Signed block did not validate."))
        '''

        if not self.persistence.contains(block):
            self.persistence.add_block(block)
            self.notify_listeners(block)
            # self.update_notify(block)

        if peer == self.my_peer:
            # We created a self-signed block / initial claim, send to the neighbours
            if block.type not in self.settings.block_types_bc_disabled and not self.settings.is_hiding:
                self.send_block(block)
            return succeed((block, None)) if public_key == ANY_COUNTERPARTY_PK else succeed((block, linked))

        # This is a source block with no counterparty
        if not peer and public_key == ANY_COUNTERPARTY_PK:
            if block.type not in self.settings.block_types_bc_disabled:
                self.send_block(block)
            return succeed((block, None))

        # If there is a counterparty to sign, we send it
        self.send_block(block, address=peer.address)

        if not linked:
            # We keep track of this outstanding sign request.
            sign_deferred = Deferred()
            # Check if we are waiting for this signature response
            block_id_int = int(hexlify(block.block_id), 16) % 100000000
            if not self.request_cache.has(u'sign', block_id_int):
                self.request_cache.add(HalfBlockSignCache(self, block, sign_deferred, peer.address,
                                                          from_peer=from_peer, seq_num=from_peer_seq_num))
                return sign_deferred
            return succeed((block, None))
        else:
            # This is a claim block, send block to the neighbours
            self.send_block_pair(linked, block)
            return succeed((linked, block))

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockPayload)
    def received_half_block(self, source_address, dist, payload):
        """
        We've received a half block, either because we sent a SIGNED message to some one or we are crawling
        """
        peer = Peer(payload.public_key, source_address)
        block = self.get_block_class(payload.type).from_payload(payload, self.serializer)
        self.process_half_block(block, peer).addErrback(lambda _: None)

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockBroadcastPayload)
    def received_half_block_broadcast(self, source_address, dist, payload):
        """
        We received a half block, part of a broadcast. Disseminate it further.
        """
        payload.ttl -= 1
        block = self.get_block_class(payload.type).from_payload(payload, self.serializer)
        peer = Peer(payload.public_key, source_address)
        self.validate_persist_block(block, peer)

        if block.block_id not in self.relayed_broadcasts and payload.ttl > 0:
            if self.settings.use_informed_broadcast:
                fanout = self.settings.broadcast_fanout - 1
                self.informed_send_block(block, ttl=payload.ttl, fanout=fanout)
            else:
                reactor.callLater(0.5 * random.random(), self.send_block, block, ttl=payload.ttl)

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockPairPayload)
    def received_half_block_pair(self, source_address, dist, payload):
        """
        We received a block pair message.
        """
        block1, block2 = self.get_block_class(payload.type1).from_pair_payload(payload, self.serializer)
        self.logger.info("Received block pair %s, %s", block1, block2)
        peer = Peer(payload.public_key, source_address)
        self.validate_persist_block(block1, peer)
        self.validate_persist_block(block2, peer)

    def validate_claims(self, last_block, peer):
        from_peer = self.persistence.key_to_id(last_block.public_key)
        crawl_id = self.persistence.id_to_int(from_peer)
        if not self.request_cache.has(u"crawl", crawl_id):
            # Need to get more information from the peer to verify the claim
            # except_pack = orjson.dumps(list(self.persistence.get_known_chains(from_peer)))
            except_pack = orjson.dumps(list())
            crawl_deferred = self.send_peer_crawl_request(crawl_id, peer,
                                                          last_block.sequence_number, except_pack)
            return crawl_deferred
        else:
            return self.request_cache.get(u'crawl', crawl_id).crawl_deferred

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockPairBroadcastPayload)
    def received_half_block_pair_broadcast(self, source_address, dist, payload):
        """
        We received a half block pair, part of a broadcast. Disseminate it further.
        """
        payload.ttl -= 1
        block1, block2 = self.get_block_class(payload.type1).from_pair_payload(payload, self.serializer)
        self.validate_persist_block(block1)
        self.validate_persist_block(block2)

        if block1.block_id not in self.relayed_broadcasts and payload.ttl > 0:
            if self.settings.use_informed_broadcast:
                fanout = self.settings.broadcast_fanout - 1
                self.informed_send_block(block1, block2, ttl=payload.ttl, fanout=fanout)
            else:
                reactor.callLater(0.5 * random.random(), self.send_block_pair, block1, block2, ttl=payload.ttl)

    def update_notify(self, block):
        self.network.known_network.add_edge(block.public_key, block.link_public_key)
        block_stat_file = os.path.join(os.environ['PROJECT_DIR'], 'output', 'leader_blocks_time_'
                                       + str(self.settings.my_id) + '.csv')

        with open(block_stat_file, "a") as t_file:
            writer = csv.DictWriter(t_file, ['time', 'transaction', "seq_num", "link"])
            writer.writerow({"time": time.time(), 'transaction': str(block.transaction),
                             'seq_num': block.sequence_number, "link": block.link_sequence_number
                             })

    def validate_persist_block(self, block, peer=None):
        """
        Validate a block and if it's valid, persist it. Return the validation result.
        :param block: The block to validate and persist.
        :return: [ValidationResult]
        """
        validation = block.validate(self.persistence)
        self.network.known_network.add_edge(block.public_key, block.link_public_key)
        if not self.settings.ignore_validation and validation[0] == ValidationResult.invalid:
            pass
        else:
            self.notify_listeners(block)
            if not self.persistence.contains(block):
                self.persistence.add_block(block)
                if peer:
                    self.persistence.add_peer(peer)
        return validation

    def notify_listeners(self, block):
        """
        Notify listeners of a specific new block.
        """
        # Call the listeners associated to the universal block, if there are any
        for listener in self.listeners_map.get(self.UNIVERSAL_BLOCK_LISTENER, []):
            listener.received_block(block)

        # Avoid proceeding any further if the type of the block coincides with the UNIVERSAL_BLOCK_LISTENER
        if block.type not in self.listeners_map or self.shutting_down or block.type == self.UNIVERSAL_BLOCK_LISTENER:
            return

        for listener in self.listeners_map[block.type]:
            listener.received_block(block)

    @synchronized
    def process_half_block(self, blk, peer):
        """
        Process a received half block.
        """
        validation = self.validate_persist_block(blk, peer)
        self.logger.info("Block validation result %s, %s, (%s)", validation[0], validation[1], blk)
        if not self.settings.ignore_validation and validation[0] == ValidationResult.invalid:
            return fail(RuntimeError("Block could not be validated: %s, %s" % (validation[0], validation[1])))

        # Check if we are waiting for this signature response
        # self.update_notify(blk)
        link_block_id_int = int(hexlify(blk.linked_block_id), 16) % 100000000
        if self.request_cache.has(u'sign', link_block_id_int):
            cache = self.request_cache.pop(u'sign', link_block_id_int)
            # We cannot guarantee that we're on a reactor thread so make sure we do this Twisted stuff on the reactor.
            reactor.callFromThread(cache.sign_deferred.callback, (blk, self.persistence.get_linked(blk)))
            if 'condition' in blk.transaction and cache.from_peer:
                # We need to answer to prev peer in the chain
                if 'proof' in blk.transaction:
                    orig_blk = self.persistence.get(cache.from_peer.public_key.key_to_bin(), cache.seq_num)
                    new_tx = orig_blk.transaction
                    new_tx['proof'] = blk.transaction['proof']
                    return self.sign_block(cache.from_peer, linked=orig_blk, block_type=b'claim',
                                           additional_info=new_tx)
                else:
                    self.logger.error("Got conditional block without a proof %s ", cache.from_peer)
                    return fail(RuntimeError("Block could not be validated: %s, %s" % (validation[0], validation[1])))

        # Is this a request, addressed to us, and have we not signed it already?
        if (blk.link_sequence_number != UNKNOWN_SEQ
                or blk.link_public_key != self.my_peer.public_key.key_to_bin()
                or self.persistence.get_linked(blk) is not None):
            return succeed(None)

        self.logger.info("Received request block addressed to us (%s)", blk)

        def on_should_sign_outcome(should_sign):
            if not should_sign:
                self.logger.info("Not signing block %s", blk)
                return succeed(None)

            peer_id = self.persistence.key_to_id(blk.public_key)
            if blk.type == b'spend':
                if self.persistence.get_balance(peer_id) < 0:
                    crawl_deferred = self.validate_claims(blk, peer)
                    return addCallback(crawl_deferred, lambda _: self.process_half_block(blk, peer))
                if 'condition' in blk.transaction:
                    pub_key = unhexlify(blk.transaction['condition'])
                    if self.my_peer.public_key.key_to_bin() != pub_key:
                        # This is a multi-hop conditional transaction, relay to next peer
                        # TODO: add to settings fees
                        fees = 0
                        spend_value = blk.transaction['value'] - fees
                        new_tx = blk.transaction
                        val = self.prepare_spend_transaction(pub_key, spend_value)
                        if not val:
                            # need to mint new values
                            mint = self.prepare_mint_transaction()
                            return addCallback(self.self_sign_block(block_type=b'claim', transaction=mint),
                                               lambda _: self.process_half_block(blk, peer))
                        next_peer, added = val
                        new_tx.update(added)
                        return self.sign_block(next_peer, next_peer.public_key.key_to_bin(), transaction=new_tx,
                                               block_type=blk.type, from_peer=peer,
                                               from_peer_seq_num=blk.sequence_number)
                    else:
                        # Conditional block that terminates at our peer: add additional_info and send claim
                        sign = blk.crypto.create_signature(self.my_peer.key, blk.transaction['nonce'].encode())
                        new_tx = blk.transaction
                        new_tx['proof'] = hexlify(sign).decode()
                        return self.sign_block(peer, linked=blk, block_type=b'claim', additional_info=new_tx)

                return self.sign_block(peer, linked=blk, block_type=b'claim')

        # determine if we want to sign this block
        return addCallback(self.should_sign(blk), on_should_sign_outcome)

    @synchronized
    @lazy_wrapper(GlobalTimeDistributionPayload, PeerCrawlResponsePayload)
    def received_peer_crawl_response(self, peer, dist, payload: PeerCrawlResponsePayload):

        cache = self.request_cache.get(u"crawl", payload.crawl_id)
        if cache:
            peer_id = self.persistence.int_to_id(payload.crawl_id)
            self.logger.info("Dump chain for %s, balance before is %s", peer_id, self.persistence.get_balance(peer_id))
            res = self.persistence.dump_peer_status(peer_id, orjson.loads(payload.chain))
            self.logger.info("Dump chain for %s, balance after is %s", peer_id, self.persistence.get_balance(peer_id))
            if res:
                cache.received_block(1, 1)
            else:
                cache.received_empty_response()
        else:
            self.logger.error("Received peer crawl with unknown crawl id %s", payload.crawl_id)

    def send_peer_crawl_response(self, peer, crawl_id, chain):
        """
        Send chain to response for the peer crawl
        """
        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = PeerCrawlResponsePayload(crawl_id, chain).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 9, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

    @synchronized
    @lazy_wrapper(GlobalTimeDistributionPayload, PeerCrawlRequestPayload)
    def received_peer_crawl_request(self, peer, dist, payload: PeerCrawlRequestPayload):

        # Need to convince peer with minimum number of blocks send
        # Get latest pairwise blocks/ including self claims

        peer_id = self.persistence.int_to_id(payload.crawl_id)
        pack_except = set(orjson.loads(payload.pack_except))
        status = self.persistence.get_peer_status(peer_id)
        s1 = orjson.dumps(status)
        self.logger.info("Received peer crawl from node %s for range, sending status len %s",
                         hexlify(peer.public_key.key_to_bin())[-8:], len(s1))
        self.send_peer_crawl_response(peer, payload.crawl_id, s1)

    def send_peer_crawl_request(self, crawl_id, peer, seq_num, pack_except):
        """
        Send a crawl request to a specific peer.
        """
        crawl_deferred = Deferred()
        self.request_cache.add(CrawlRequestCache(self, crawl_id, crawl_deferred))
        self.logger.info("Requesting balance proof for peer %s at seq num %d with id %d",
                         hexlify(peer.public_key.key_to_bin())[-8:], seq_num, crawl_id)

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = PeerCrawlRequestPayload(seq_num, crawl_id, pack_except).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 8, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)
        return crawl_deferred

    def crawl_chain(self, peer, latest_block_num=0):
        """
        Crawl the whole chain of a specific peer.
        :param latest_block_num: The latest block number of the peer in question, if available.
        """
        crawl_deferred = Deferred()
        cache = ChainCrawlCache(self, peer, crawl_deferred, known_chain_length=latest_block_num)
        self.request_cache.add(cache)
        reactor.callFromThread(self.send_next_partial_chain_crawl_request, cache)
        return crawl_deferred

    def crawl_lowest_unknown(self, peer, latest_block_num=None):
        """
        Crawl the lowest unknown block of a specific peer.
        :param latest_block_num: The latest block number of the peer in question, if available
        """
        sq = self.persistence.get_lowest_sequence_number_unknown(peer.public_key.key_to_bin())
        if latest_block_num and sq == latest_block_num + 1:
            return succeed([])  # We don't have to crawl this node since we have its whole chain
        return self.send_crawl_request(peer, peer.public_key.key_to_bin(), sq, sq)

    def send_crawl_request(self, peer, public_key, start_seq_num, end_seq_num, for_half_block=None):
        """
        Send a crawl request to a specific peer.
        """
        crawl_id = for_half_block.hash_number if for_half_block else \
            RandomNumberCache.find_unclaimed_identifier(self.request_cache, u"crawl")
        crawl_deferred = Deferred()
        self.request_cache.add(CrawlRequestCache(self, crawl_id, crawl_deferred))
        self.logger.info("Requesting crawl of node %s (blocks %d to %d) with id %d",
                         hexlify(peer.public_key.key_to_bin())[-8:], start_seq_num, end_seq_num, crawl_id)

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = CrawlRequestPayload(public_key, start_seq_num, end_seq_num, crawl_id).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 2, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

        return crawl_deferred

    def perform_partial_chain_crawl(self, cache, start, stop):
        """
        Perform a partial crawl request for a specific range, when crawling a chain.
        :param cache: The cache that stores progress regarding the chain crawl.
        :param start: The sequence number of the first block to be requested.
        :param stop: The sequence number of the last block to be requested.
        """
        if cache.current_request_range != (start, stop):
            # We are performing a new request
            cache.current_request_range = start, stop
            cache.current_request_attempts = 0
        elif cache.current_request_attempts == 3:
            # We already tried the same request three times, bail out
            self.request_cache.pop(u"chaincrawl", cache.number)
            cache.crawl_deferred.callback(None)
            return

        cache.current_request_attempts += 1
        cache.current_crawl_deferred = self.send_crawl_request(cache.peer, cache.peer.public_key.key_to_bin(),
                                                               start, stop)
        addCallback(cache.current_crawl_deferred, lambda _: self.send_next_partial_chain_crawl_request(cache))

    def send_next_partial_chain_crawl_request(self, cache):
        """
        Send the next partial crawl request, if we are not done yet.
        :param cache: The cache that stores progress regarding the chain crawl.
        """
        lowest_unknown = self.persistence.get_lowest_sequence_number_unknown(cache.peer.public_key.key_to_bin())
        if cache.known_chain_length and cache.known_chain_length == lowest_unknown - 1:
            # At this point, we have all the blocks we need
            self.request_cache.pop(u"chaincrawl", cache.number)
            cache.crawl_deferred.callback(None)
            return

        # Do we know the chain length of the crawled peer? If not, make sure we get to know this first.
        def on_latest_block(blocks):
            if not blocks:
                self.request_cache.pop(u"chaincrawl", cache.number)
                cache.crawl_deferred.callback(None)
                return

            cache.known_chain_length = blocks[0].sequence_number
            self.send_next_partial_chain_crawl_request(cache)

        if not cache.known_chain_length:
            self.send_crawl_request(cache.peer, cache.peer.public_key.key_to_bin(), -1, -1).addCallback(on_latest_block)
            return

        latest_block = self.persistence.get_latest(cache.peer.public_key.key_to_bin())
        if not latest_block:
            # We have no knowledge of this peer but we have the length of the chain.
            # Simply send a request from the genesis block to the known chain length.
            self.perform_partial_chain_crawl(cache, 1, cache.known_chain_length)
            return
        elif latest_block and lowest_unknown == latest_block.sequence_number + 1:
            # It seems that we filled all gaps in the database; check whether we can do one final request
            if latest_block.sequence_number < cache.known_chain_length:
                self.perform_partial_chain_crawl(cache, latest_block.sequence_number + 1, cache.known_chain_length)
                return
            else:
                self.request_cache.pop(u"chaincrawl", cache.number)
                cache.crawl_deferred.callback(None)
                return

        start, stop = self.persistence.get_lowest_range_unknown(cache.peer.public_key.key_to_bin())
        self.perform_partial_chain_crawl(cache, start, stop)

    @synchronized
    @lazy_wrapper(GlobalTimeDistributionPayload, CrawlRequestPayload)
    def received_crawl_request(self, peer, dist, payload):
        self.logger.info("Received crawl request from node %s for range %d-%d",
                         hexlify(peer.public_key.key_to_bin())[-8:], payload.start_seq_num, payload.end_seq_num)
        start_seq_num = payload.start_seq_num
        end_seq_num = payload.end_seq_num

        # It could be that our start_seq_num and end_seq_num are negative. If so, convert them to positive numbers,
        # based on the last block of ones chain.
        if start_seq_num < 0:
            last_block = self.persistence.get_latest(payload.public_key)
            start_seq_num = max(GENESIS_SEQ, last_block.sequence_number + start_seq_num + 1) \
                if last_block else GENESIS_SEQ
        if end_seq_num < 0:
            last_block = self.persistence.get_latest(payload.public_key)
            end_seq_num = max(GENESIS_SEQ, last_block.sequence_number + end_seq_num + 1) \
                if last_block else GENESIS_SEQ

        blocks = self.persistence.crawl(payload.public_key, start_seq_num, end_seq_num, limit=10)
        total_count = len(blocks)

        if total_count == 0:
            global_time = self.claim_global_time()
            response_payload = EmptyCrawlResponsePayload(payload.crawl_id).to_pack_list()
            dist = GlobalTimeDistributionPayload(global_time).to_pack_list()
            packet = self._ez_pack(self._prefix, 7, [dist, response_payload], False)
            self.endpoint.send(peer.address, packet)
        else:
            self.send_crawl_responses(blocks, peer, payload.crawl_id)

    def send_crawl_responses(self, blocks, peer, crawl_id):
        """
        Answer a peer with crawl responses.
        """
        for ind, block in enumerate(blocks):
            self.send_crawl_response(block, crawl_id, ind + 1, len(blocks), peer)
        self.logger.info("Sent %d blocks", len(blocks))

    @synchronized
    def sanitize_database(self):
        """
        DANGER! USING THIS MAY CAUSE DOUBLE SPENDING IN THE NETWORK.
                ONLY USE IF YOU KNOW WHAT YOU ARE DOING.

        This method removes all of the invalid blocks in our own chain.
        """
        self.logger.error("Attempting to recover %s", self.DB_CLASS.__name__)
        block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
        if not block:
            # There is nothing to corrupt, we're at the genesis block.
            self.logger.debug("No latest block found when trying to recover database!")
            return
        validation = self.validate_persist_block(block)
        while not self.settings.ignore_validation and validation[0] != ValidationResult.partial_next \
                and validation[0] != ValidationResult.valid:
            # The latest block is invalid, remove it.
            self.persistence.remove_block(block)
            self.logger.error("Removed invalid block %d from our chain", block.sequence_number)
            block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
            if not block:
                # Back to the genesis
                break
            validation = self.validate_persist_block(block)
        self.logger.error("Recovered database, our last block is now %d", block.sequence_number if block else 0)

    def persistence_integrity_check(self):
        """
        Perform an integrity check of our own chain. Recover it if needed.
        """
        block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
        if not block:
            return
        validation = self.validate_persist_block(block)
        if not self.settings.ignore_validation and validation[0] != ValidationResult.partial_next \
                and validation[0] != ValidationResult.valid:
            self.logger.error("Our chain did not validate. Result %s", repr(validation))
            self.sanitize_database()

    def send_crawl_response(self, block, crawl_id, index, total_count, peer):
        self.logger.debug("Sending block for crawl request to %s (%s)", peer, block)

        # Don't answer with any invalid blocks.
        validation = self.validate_persist_block(block)
        if not self.settings.ignore_validation and validation[0] == ValidationResult.invalid and total_count > 0:
            # We send an empty block to the crawl requester if no blocks should be sent back
            self.logger.error("Not sending crawl response, the block is invalid. Result %s", repr(validation))
            self.persistence_integrity_check()
            return

        global_time = self.claim_global_time()
        payload = CrawlResponsePayload.from_crawl(block, crawl_id, index, total_count).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 3, [dist, payload], False)
        self.endpoint.send(peer.address, packet)

    @synchronized
    @lazy_wrapper_unsigned_wd(GlobalTimeDistributionPayload, CrawlResponsePayload)
    def received_crawl_response(self, source_address, dist, payload, data):
        self.received_half_block(source_address, data[:-12])  # We cut off a few bytes to make it a BlockPayload

        block = self.get_block_class(payload.type).from_payload(payload, self.serializer)
        cache = self.request_cache.get(u"crawl", payload.crawl_id)
        if cache:
            cache.received_block(block, payload.total_count)

    @lazy_wrapper_unsigned_wd(GlobalTimeDistributionPayload, EmptyCrawlResponsePayload)
    def received_empty_crawl_response(self, source_address, dist, payload, data):
        cache = self.request_cache.get(u"crawl", payload.crawl_id)
        if cache:
            self.logger.info("Received empty crawl response for crawl with ID %d", payload.crawl_id)
            cache.received_empty_response()

    def get_chain_length(self):
        """
        Return the length of your own chain.
        """
        latest_block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
        return 0 if not latest_block else latest_block.sequence_number

    @synchronized
    def create_introduction_request(self, socket_address, extra_bytes=b''):
        extra_bytes = struct.pack('>l', self.get_chain_length())
        return super(TrustChainCommunity, self).create_introduction_request(socket_address, extra_bytes)

    @synchronized
    def create_introduction_response(self, lan_socket_address, socket_address, identifier,
                                     introduction=None, extra_bytes=b''):
        extra_bytes = struct.pack('>l', self.get_chain_length())
        return super(TrustChainCommunity, self).create_introduction_response(lan_socket_address, socket_address,
                                                                             identifier, introduction, extra_bytes)

    def defered_sync_start(self, mid):
        self.periodic_sync_lc[mid].start(self.settings.sync_time)

    def defered_sync_stop(self, mid):
        self.periodic_sync_lc[mid].stop()

    def all_sync_stop(self):
        for mid in self.pex:
            self.defered_sync_stop(mid)

    @synchronized
    def introduction_response_callback(self, peer, dist, payload):
        chain_length = None
        if payload.extra_bytes:
            chain_length = struct.unpack('>l', payload.extra_bytes)[0]

        if peer.address in self.network.blacklist:  # Do not crawl addresses in our blacklist (trackers)
            return

        if not self.ipv8:
            self.logger.error('No IPv8 service object available, cannot start PEXCommunity')
        elif peer.mid not in self.pex:
            community = SubTrustCommunity(self.my_peer, self.ipv8.endpoint, Network(), mid=peer.mid)
            index = len(self.ipv8.overlays)
            self.ipv8.overlays.append(community)
            # Discover and connect to everyone for 50 seconds
            #
            self.pex[peer.mid] = community
            self.pex_map[peer.mid] = index
            if self.bootstrap_master:
                self.logger.info('Proceed with a bootstrap master')
                for k in self.bootstrap_master:
                    community.walk_to(k)
            else:
                self.ipv8.strategies.append((RandomWalk(community, total_run=self.settings.intro_run), -1))
            # Start sync task after the discovery
            self.periodic_sync_lc[peer.mid] = self.register_task("sync_" + str(peer.mid),
                                                                 LoopingCall(self.trustchain_sync, peer.mid))
            self.register_anonymous_task("sync_start_" + str(peer.mid),
                                         reactor.callLater(self.settings.intro_run +
                                                           self.settings.sync_time * random.random(),
                                                           self.defered_sync_start, peer.mid))

        # Check if we have pending crawl requests for this peer
        has_intro_crawl = self.request_cache.has(u"introcrawltimeout", IntroCrawlTimeout.get_number_for(peer))
        has_chain_crawl = self.request_cache.has(u"chaincrawl", ChainCrawlCache.get_number_for(peer))
        if has_intro_crawl or has_chain_crawl:
            self.logger.debug("Skipping crawl of peer %s, another crawl is pending", peer)
            return

        if self.settings.crawler:
            self.crawl_chain(peer, latest_block_num=chain_length)
        else:
            known_blocks = self.persistence.get_number_of_known_blocks(public_key=peer.public_key.key_to_bin())
            if known_blocks < 1000 or random.random() > 0.5:
                self.request_cache.add(IntroCrawlTimeout(self, peer))
                self.crawl_lowest_unknown(peer, latest_block_num=chain_length)

    def unload(self):
        self.logger.debug("Unloading the TrustChain Community.")
        self.shutting_down = True

        self.request_cache.shutdown()

        super(TrustChainCommunity, self).unload()

        # Close the persistence layer
        self.persistence.close()


class TrustChainTestnetCommunity(TrustChainCommunity):
    """
    This community defines the testnet for TrustChain
    """
    DB_NAME = 'trustchain_testnet'

    master_peer = Peer(unhexlify("4c69624e61434c504b3aa90c1e65d68e9f0ccac1385b58e4a605add2406aff9952b1b6435ab07e5385"
                                 "5eb07b062ca33af9ec55b45446dbbefc3752523a4fd3b659ecd1d8e172b7b7f30d"))
