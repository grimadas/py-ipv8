from __future__ import absolute_import

from twisted.internet.defer import inlineCallbacks

from ...base import TestBase
from ...mocking.ipv8 import MockIPv8
from ....attestation.noodle.block import NoodleBlock
from ....attestation.noodle.community import NoodleCommunity
from ....attestation.noodle.exceptions import InsufficientBalanceException, NoPathFoundException
from ....attestation.noodle.listener import BlockListener
from ....attestation.noodle.settings import NoodleSettings, SecurityMode


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

        # Make sure everyone knows the minter (first peer)
        for node_ind in range(1, len(self.nodes)):
            minter_pk = self.nodes[0].overlay.my_peer.public_key.key_to_bin()
            self.nodes[node_ind].overlay.known_graph.add_node(minter_pk, minter=True)

        self.nodes[0].overlay.init_minter_community()

    def create_node(self):
        ipv8 = MockIPv8(u"curve25519", NoodleCommunity, working_directory=u":memory:")
        ipv8.overlay.ipv8 = ipv8

        return ipv8


class TestNoodleCommunityTwoNodes(TestNoodleCommunityBase):
    __testing__ = True

    def test_transfer_insufficient_balance(self):
        """
        Verify if a transfer is not made when overspending.
        """
        def on_success(_):
            # Should never trigger!
            self.assertTrue(False)

        def on_failure(exc):
            self.assertEqual(exc.type, InsufficientBalanceException)

        self.nodes[0].overlay.persistence.get_balance = lambda _, verified=True: 0
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

        self.nodes[0].overlay.persistence.get_balance = lambda _, verified=True: 10000
        return self.nodes[0].overlay.transfer(self.nodes[1].overlay.my_peer, 100).addCallbacks(on_success, on_failure)

    @inlineCallbacks
    def test_transfer_full_risk(self):
        """
        Test a successful transfer with audits and full risk.
        """
        self.nodes[1].overlay.settings.risk = 1

        yield self.introduce_nodes()
        yield self.nodes[0].overlay.transfer(self.nodes[1].overlay.my_peer, 10)

        my_pk = self.nodes[0].overlay.my_peer.public_key.key_to_bin()
        my_id = self.nodes[0].overlay.persistence.key_to_id(my_pk)
        self.assertEqual(self.nodes[0].overlay.persistence.get_balance(my_id),
                         self.nodes[0].overlay.settings.initial_mint_value - 10)

        my_pk = self.nodes[1].overlay.my_peer.public_key.key_to_bin()
        my_id = self.nodes[1].overlay.persistence.key_to_id(my_pk)
        self.assertEqual(self.nodes[1].overlay.persistence.get_balance(my_id),
                         self.nodes[1].overlay.settings.initial_mint_value + 10)

    @inlineCallbacks
    def test_transfer_no_risk(self):
        """
        Test a successful transfer with audits and no risk.
        """
        yield self.introduce_nodes()
        yield self.nodes[0].overlay.transfer(self.nodes[1].overlay.my_peer, 10)

        my_pk = self.nodes[0].overlay.my_peer.public_key.key_to_bin()
        my_id = self.nodes[0].overlay.persistence.key_to_id(my_pk)
        self.assertEqual(self.nodes[0].overlay.persistence.get_balance(my_id),
                         self.nodes[0].overlay.settings.initial_mint_value - 10)

        my_pk = self.nodes[1].overlay.my_peer.public_key.key_to_bin()
        my_id = self.nodes[1].overlay.persistence.key_to_id(my_pk)
        self.assertEqual(self.nodes[1].overlay.persistence.get_balance(my_id),
                         self.nodes[1].overlay.settings.initial_mint_value + 10)

    @inlineCallbacks
    def test_transfer_no_risk_multiple(self):
        """
        Test multiple transfers in quick succession with audits and no risk.
        """
        yield self.introduce_nodes()
        for _ in range(5):
            self.nodes[0].overlay.transfer(self.nodes[1].overlay.my_peer, 10)

        yield self.sleep(1)

        my_pk = self.nodes[0].overlay.my_peer.public_key.key_to_bin()
        my_id = self.nodes[0].overlay.persistence.key_to_id(my_pk)
        self.assertEqual(self.nodes[0].overlay.persistence.get_balance(my_id),
                         self.nodes[0].overlay.settings.initial_mint_value - 50)

        my_pk = self.nodes[1].overlay.my_peer.public_key.key_to_bin()
        my_id = self.nodes[1].overlay.persistence.key_to_id(my_pk)
        self.assertEqual(self.nodes[1].overlay.persistence.get_balance(my_id),
                         self.nodes[1].overlay.settings.initial_mint_value + 50)

    @inlineCallbacks
    def test_make_random_transfer(self):
        """
        Test making a random transfer.
        """
        yield self.introduce_nodes()
        self.nodes[1].overlay.make_random_transfer()  # Should make the payment now
        yield self.sleep(0.2)

        my_pk = self.nodes[1].overlay.my_peer.public_key.key_to_bin()
        my_id = self.nodes[1].overlay.persistence.key_to_id(my_pk)
        self.assertEqual(self.nodes[1].overlay.persistence.get_balance(my_id),
                         self.nodes[1].overlay.settings.initial_mint_value - 1)

    @inlineCallbacks
    def test_make_random_transfer_ping_timeout(self):
        """
        Test that we are not making transactions if the ping to the other peer times out.
        """
        yield self.introduce_nodes()
        self.nodes[0].overlay.settings.ping_timeout = 0.1
        self.nodes[1].overlay.decode_map[chr(15)] = lambda *_: None  # Ignore incoming pings

        self.nodes[0].overlay.make_random_transfer()

        yield self.sleep(0.2)  # Let the ping timeout

        my_pub_key = self.nodes[0].overlay.my_peer.public_key.key_to_bin()
        latest_blocks = self.nodes[0].overlay.persistence.get_latest_blocks(my_pub_key)
        self.assertEqual(len(latest_blocks), 1)

    @inlineCallbacks
    def test_transfer_overspend(self):
        """
        Test an overspend transaction.
        """
        yield self.introduce_nodes()
        self.nodes[0].overlay.persistence.get_balance = lambda _, verified=True: self.nodes[0].overlay.settings.initial_mint_value + 1
        self.nodes[0].overlay.transfer(self.nodes[1].overlay.my_peer, self.nodes[0].overlay.settings.initial_mint_value + 1)
        yield self.sleep(0.5)

        # The block should not be counter-signed
        my_pub_key = self.nodes[1].overlay.my_peer.public_key.key_to_bin()
        latest_blocks = self.nodes[1].overlay.persistence.get_latest_blocks(my_pub_key)
        self.assertEqual(len(latest_blocks), 1)

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
                         self.nodes[0].overlay.settings.initial_mint_value * 2)


class TestNoodleCommunityThreeNodes(TestNoodleCommunityBase):
    __testing__ = True
    NUM_NODES = 3

    @inlineCallbacks
    def test_transfer_chain(self):
        """
        Test transferring funds from minter to A and then from A to B.
        """
        yield self.introduce_nodes()
        yield self.nodes[0].overlay.transfer(self.nodes[1].overlay.my_peer, 10)
        yield self.nodes[1].overlay.transfer(self.nodes[2].overlay.my_peer, 10)

        # Check balances
        my_pk = self.nodes[0].overlay.my_peer.public_key.key_to_bin()
        my_id = self.nodes[0].overlay.persistence.key_to_id(my_pk)
        self.assertEqual(self.nodes[0].overlay.persistence.get_balance(my_id),
                         self.nodes[0].overlay.settings.initial_mint_value - 10)

        my_pk = self.nodes[1].overlay.my_peer.public_key.key_to_bin()
        my_id = self.nodes[1].overlay.persistence.key_to_id(my_pk)
        self.assertEqual(self.nodes[1].overlay.persistence.get_balance(my_id),
                         self.nodes[1].overlay.settings.initial_mint_value)

        my_pk = self.nodes[2].overlay.my_peer.public_key.key_to_bin()
        my_id = self.nodes[2].overlay.persistence.key_to_id(my_pk)
        self.assertEqual(self.nodes[2].overlay.persistence.get_balance(my_id),
                         self.nodes[2].overlay.settings.initial_mint_value + 10)

    @inlineCallbacks
    def test_transfer_chain_overspend(self):
        """
        Test transferring funds from minter to A and then from A to B. The final transfer will be an overspend.
        """
        yield self.introduce_nodes()
        yield self.nodes[0].overlay.transfer(self.nodes[1].overlay.my_peer, 1)
        self.nodes[1].overlay.persistence.get_balance = lambda _, verified=True: self.nodes[1].overlay.settings.initial_mint_value + 2
        self.nodes[1].overlay.transfer(self.nodes[2].overlay.my_peer, self.nodes[1].overlay.settings.initial_mint_value + 2)

        yield self.sleep(0.3)

        # The block should not be counter-signed
        my_pub_key = self.nodes[2].overlay.my_peer.public_key.key_to_bin()
        latest_blocks = self.nodes[2].overlay.persistence.get_latest_blocks(my_pub_key)
        self.assertEqual(len(latest_blocks), 1)


class TestNoodleCommunityFiveNodes(TestNoodleCommunityBase):
    __testing__ = True
    NUM_NODES = 5

    @inlineCallbacks
    def test_transfer_twice(self):
        """
        Test transferring some funds to different entities.
        """
        initial_value = self.nodes[0].overlay.settings.initial_mint_value
        yield self.introduce_nodes()
        yield self.nodes[0].overlay.transfer(self.nodes[1].overlay.my_peer,
                                             self.nodes[0].overlay.settings.initial_mint_value)

        self.nodes[1].overlay.persistence.get_balance = lambda _, verified=True: initial_value * 3
        yield self.nodes[1].overlay.transfer(self.nodes[2].overlay.my_peer, initial_value * 2)
        self.nodes[1].overlay.transfer(self.nodes[3].overlay.my_peer, initial_value)

        # The block should not be counter-signed by node 3
        my_pub_key = self.nodes[3].overlay.my_peer.public_key.key_to_bin()
        latest_blocks = self.nodes[3].overlay.persistence.get_latest_blocks(my_pub_key)
        self.assertEqual(len(latest_blocks), 1)

    # @inlineCallbacks
    # def test_double_spend_hiding(self):
    #     """
    #     Test transfer with hiding
    #     """
    #     self.nodes[1].overlay.settings.is_hiding = True
    #     yield self.introduce_nodes()
    #     yield self.nodes[0].overlay.transfer(self.nodes[1].overlay.my_peer, 10)
    #     yield self.nodes[1].overlay.transfer(self.nodes[2].overlay.my_peer, 6)
    #     yield self.nodes[1].overlay.transfer(self.nodes[0].overlay.my_peer, 6)
    #
    #     pk_2 = self.nodes[1].overlay.my_peer.public_key.key_to_bin()
    #     id_2 = self.nodes[0].overlay.persistence.key_to_id(pk_2)
    #
    #     yield self.sleep(1.0)
    #     self.assertLess(self.nodes[2].overlay.persistence.get_balance(id_2), 0)
