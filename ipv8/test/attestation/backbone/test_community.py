from asyncio import sleep

from ...base import TestBase
from ....peer import Peer
from ...mocking.ipv8 import MockIPv8
from ....attestation.backbone.block import NoodleBlock
from ....attestation.backbone.community import NoodleCommunity
from ....keyvault.crypto import default_eccrypto


class DummyBlock(NoodleBlock):
    """
    This dummy block is used to verify the conversion to a specific block class during the tests.
    Other than that, it has no purpose.
    """
    pass


class TestNoodleCommunityBase(TestBase):
    __testing__ = False
    NUM_NODES = 2

    def setUp(self):
        super(TestNoodleCommunityBase, self).setUp()
        self.initialize(NoodleCommunity, self.NUM_NODES)

        # Make sure every node has a community to listen to
        self.community_key = default_eccrypto.generate_key(u"curve25519").pub()
        self.community_id = self.community_key.key_to_bin()
        com_peer = Peer(self.community_key)
        for node in self.nodes:
            node.overlay.subscribe_to_community(com_peer)

    def create_node(self):
        ipv8 = MockIPv8(u"curve25519", NoodleCommunity, working_directory=u":memory:")
        ipv8.overlay.ipv8 = ipv8

        return ipv8

    async def test_basic_vertical_chain_sync(self):
        """
        Check whether two parties can track each others vertical chains
        """
        self.nodes[0].overlay.settings.track_neighbours_chains = True
        self.nodes[1].overlay.settings.track_neighbours_chains = True
        await self.introduce_nodes()

        # Have node 0 create a block
        block = await self.nodes[0].overlay.sign_block(list(self.nodes[0].network.verified_peers)[0], block_type=b'test', transaction={})
        await self.deliver_messages()

        # Node 1 should now have the block in its database
        self.assertTrue(self.nodes[1].overlay.persistence.get(block.public_key, block.sequence_number))


class TestNoodleCommunityTwoNodes(TestNoodleCommunityBase):
    __testing__ = True

    async def test_basic_horizontal_chain_no_conclict_one_tx(self):
        """
        Test a very basic horizontal chain where one node creates a block in a horizontal community.
        """
        # Create a new block now in that community
        self.nodes[0].overlay.sign_block(self.nodes[0].overlay.my_peer,
                                         com_id=self.community_id, block_type=b'test', transaction={})

        await sleep(1)

        self.assertTrue(self.nodes[1].overlay.persistence.get_frontier(self.community_id))

    async def test_basic_horizontal_chain_no_conclict_two_txs(self):
        """
        Test a very basic horizontal chain where one node creates a block in a horizontal community,
        and another node builds upon that.
        """
        self.nodes[0].overlay.sign_block(self.nodes[0].overlay.my_peer,
                                         com_id=self.community_id, block_type=b'test', transaction={})
        await sleep(1)

        block = await self.nodes[1].overlay.sign_block(self.nodes[1].overlay.my_peer,
                                                       com_id=self.community_id, block_type=b'test', transaction={})
        self.assertTrue(block.links)
        await sleep(1)

        # The frontier should now be the block created by peer 1
        frontier = self.nodes[0].overlay.persistence.get_frontier(self.community_id)
        self.assertFalse(frontier['p'])
        self.assertTrue(frontier['v'])

    async def test_basic_horizontal_chain_no_conclict_three_txs(self):
        """
        Test a very basic horizontal chain where nodes creates a block in a horizontal community simultaneously,
        and another node builds upon that.
        """
        self.nodes[0].overlay.sign_block(self.nodes[0].overlay.my_peer,
                                         com_id=self.community_id, block_type=b'test', transaction={})
        self.nodes[1].overlay.sign_block(self.nodes[1].overlay.my_peer,
                                         com_id=self.community_id, block_type=b'test', transaction={})
        await sleep(1)

        # The frontier should now be two blocks
        frontier = self.nodes[0].overlay.persistence.get_frontier(self.community_id)
        self.assertEqual(len(list(frontier['v'])), 2)

        block = await self.nodes[1].overlay.sign_block(self.nodes[1].overlay.my_peer,
                                                       com_id=self.community_id, block_type=b'test', transaction={})
        self.assertEqual(len(list(block.links)), 2)
        await sleep(1)

        # The frontier should now be the block created by peer 1
        frontier = self.nodes[0].overlay.persistence.get_frontier(self.community_id)
        self.assertEqual(len(list(frontier['v'])), 1)

    async def test_basic_horizontal_chain_conclict_three_txs(self):
        """
        Test a basic horizontal chain with conflicts.
        """
        await self.introduce_nodes()

        self.nodes[0].endpoint.close()
        self.nodes[1].endpoint.close()

        self.nodes[0].overlay.sign_block(self.nodes[0].overlay.my_peer,
                                         com_id=self.community_id, block_type=b'test', transaction={})
        self.nodes[1].overlay.sign_block(self.nodes[1].overlay.my_peer,
                                         com_id=self.community_id, block_type=b'test', transaction={})
        self.nodes[0].overlay.sign_block(self.nodes[0].overlay.my_peer,
                                         com_id=self.community_id, block_type=b'test', transaction={})
        self.nodes[1].overlay.sign_block(self.nodes[1].overlay.my_peer,
                                         com_id=self.community_id, block_type=b'test', transaction={})

        self.nodes[0].endpoint.open()
        self.nodes[1].endpoint.open()

        await sleep(2) # This requires two rounds for reconciliation (each in 1 second)

        frontier_a = self.nodes[0].overlay.persistence.get_frontier(self.community_id)
        frontier_b = self.nodes[1].overlay.persistence.get_frontier(self.community_id)
        self.assertEqual(frontier_a, frontier_b)