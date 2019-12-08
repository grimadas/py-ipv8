from __future__ import absolute_import

from twisted.internet.defer import inlineCallbacks

from ...base import TestBase
from ...mocking.ipv8 import MockIPv8
from ....attestation.noodle.block import NoodleBlock
from ....attestation.noodle.community import NoodleCommunity
from ....attestation.noodle.exceptions import InsufficientBalanceException, NoPathFoundException
from ....attestation.noodle.listener import BlockListener


class DummyBlock(NoodleBlock):
    """
    This dummy block is used to verify the conversion to a specific block class during the tests.
    Other than that, it has no purpose.
    """
    pass


class TestBlockListener(BlockListener):
    """
    This block listener simply signs all blocks it receives.
    """
    BLOCK_CLASS = DummyBlock

    def should_sign(self, block):
        return True

    def received_block(self, block):
        pass


class TestNoodleCommunity(TestBase):

    def setUp(self):
        super(TestNoodleCommunity, self).setUp()
        self.initialize(NoodleCommunity, 2)

        for node in self.nodes:
            node.overlay.add_listener(TestBlockListener(), [b'spend', b'claim'])

    def create_node(self):
        ipv8 = MockIPv8(u"curve25519", NoodleCommunity, working_directory=u":memory:")
        ipv8.overlay.ipv8 = ipv8

        return ipv8

    def test_transfer_insufficient_balance(self):
        """
        Verify if a transfer is not made when overspending.
        """
        def on_success(_):
            # Should never trigger!
            self.assertTrue(False)

        def on_failure(exc):
            self.assertEqual(exc.type, InsufficientBalanceException)

        return self.nodes[0].overlay.transfer(self.nodes[1].overlay.my_peer, 100).addCallbacks(on_success, on_failure)

    def test_transfer_no_path(self):
        """
        Verify if a transfer is not made when the peers are not connected.
        """
        def on_success(_):
            # Should never trigger!
            self.assertTrue(False)

        def on_failure(exc):
            self.assertEqual(exc.type, NoPathFoundException)

        self.nodes[0].overlay.persistence.get_balance = lambda *_, verified=True: 10000
        return self.nodes[0].overlay.transfer(self.nodes[1].overlay.my_peer, 100).addCallbacks(on_success, on_failure)

    @inlineCallbacks
    def test_transfer(self):
        """
        Test a successful transfer.
        """
        yield self.introduce_nodes()
        yield self.nodes[0].overlay.mint()
        yield self.nodes[0].overlay.transfer(self.nodes[1].overlay.my_peer, 10)

    @inlineCallbacks
    def test_mint(self):
        """
        Test minting some value.
        """
        yield self.nodes[0].overlay.mint()
        my_pub_key = self.nodes[0].overlay.my_peer.public_key.key_to_bin()
        latest_block = self.nodes[0].overlay.persistence.get_latest(my_pub_key)
        self.assertTrue(latest_block)
        self.assertEqual(latest_block.type, b'claim')

        my_pk = self.nodes[0].overlay.my_peer.public_key.key_to_bin()
        my_id = self.nodes[0].overlay.persistence.key_to_id(my_pk)
        self.assertEqual(self.nodes[0].overlay.persistence.get_balance(my_id),
                         self.nodes[0].overlay.settings.initial_mint_value)
