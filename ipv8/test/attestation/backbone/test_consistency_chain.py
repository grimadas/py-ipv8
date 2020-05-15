import asynctest

import orjson as json

from ....attestation.backbone.block import EMPTY_SIG, GENESIS_HASH, GENESIS_SEQ, NoodleBlock
from ....attestation.backbone.datastore.memory_database import NoodleMemoryDatabase
from ....attestation.backbone.datastore.utils import decode_links, encode_links, key_to_id
from ....keyvault.crypto import default_eccrypto


class TestBlock(NoodleBlock):
    """
    Test Block that simulates a block used in TrustChain.
    Also used in other test files for TrustChain.
    """

    def __init__(self, transaction=None, previous=None, key=None, links=None, com_id=None, block_type=b'test'):
        crypto = default_eccrypto
        if not links:
            links = set()
            com_seq_num = 1
        else:
            com_seq_num = max(links)[0] + 1

        if not previous:
            previous = {(0, key_to_id(GENESIS_HASH))}
        pers_seq_num = max(previous)[0] + 1

        transaction = transaction or {'id': 42}

        if not com_id:
            com_id = crypto.generate_key(u"curve25519").pub().key_to_hash()

        if key:
            self.key = key
        else:
            self.key = crypto.generate_key(u"curve25519")

        NoodleBlock.__init__(self, (block_type,
                                    json.dumps(transaction),
                                    self.key.pub().key_to_bin(),
                                    pers_seq_num,
                                    json.dumps(decode_links(previous)),
                                    json.dumps(decode_links(links)),
                                    com_id,
                                    com_seq_num,
                                    EMPTY_SIG,
                                    0, 0))
        self.sign(self.key)


class MockDatabase(NoodleMemoryDatabase):
    """
    This mocked database is only used during the tests.
    """

    def __init__(self):
        NoodleMemoryDatabase.__init__(self, '', 'mock')


class TestNoodleBlocks(asynctest.TestCase):
    """
    This class contains tests for a TrustChain block.
    """

    def test_sign(self):
        """
        Test signing a block and whether the signature is valid
        """
        crypto = default_eccrypto
        block = TestBlock()
        self.assertTrue(crypto.is_valid_signature(block.key, block.pack(signature=False), block.signature))

    def test_create_genesis(self):
        """
        Test creating a genesis block
        """
        key = default_eccrypto.generate_key(u"curve25519")
        db = MockDatabase()
        block = NoodleBlock.create(b'test', {'id': 42}, db, key.pub().key_to_bin())
        self.assertIn((0, key_to_id(GENESIS_HASH)), block.previous)
        self.assertEqual(block.public_key, key.pub().key_to_bin())
        self.assertEqual(block.signature, EMPTY_SIG)
        self.assertEqual(1, block.sequence_number)
        self.assertEqual(block.type, b'test')

    def test_create_next(self):
        """
        Test creating a block that points towards a previous block in a personal chain
        """
        db = MockDatabase()
        key = default_eccrypto.generate_key(u"curve25519")
        prev = TestBlock(key=key)
        db.add_block(prev)
        block = NoodleBlock.create(b'test', {'id': 42}, db, prev.public_key)

        self.assertEqual({(1, key_to_id(prev.hash))}, block.previous)
        self.assertEqual(block.sequence_number, 2)
        self.assertEqual(block.public_key, prev.public_key)

    def test_create_community_next(self):
        """
        Test creating a linked half block
        """
        com_key = default_eccrypto.generate_key(u"curve25519").pub().key_to_hash()
        # Generate community id
        gen = TestBlock(com_id=com_key)
        db = MockDatabase()
        db.add_block(gen)
        key = default_eccrypto.generate_key(u"curve25519")
        block = NoodleBlock.create(b'test', {'id': 42}, db, key.pub().key_to_bin(), com_id=com_key)

        self.assertEqual({(1, key_to_id(gen.hash))}, block.links)
        self.assertEqual(2, block.com_seq_num)
        self.assertEqual(com_key, block.com_id)


class TestNoodleConsistency(asynctest.TestCase):

    def test_block_no_previous(self):
        db = MockDatabase()
        block = TestBlock(previous={(1, '1234')})
        db.add_block(block)
        front = db.get_frontier(block.public_key)
        # Frontier should contain seq_num=2
        self.assertEqual(True, [2 in tuples for tuples in front['v']][0])
        # Frontier should indicate holes
        self.assertEqual([(1, 1)], front['h'])

    def test_block_no_linked(self):
        com_key = default_eccrypto.generate_key(u"curve25519").pub().key_to_hash()
        block = TestBlock(com_id=com_key, links={(1, '1234')})
        db = MockDatabase()
        db.add_block(block)
        front = db.get_frontier(com_key)
        # Frontier should contain seq_num=2
        self.assertEqual(True, [2 in tuples for tuples in front['v']][0])
        # Frontier should indicate holes
        self.assertEqual([(1, 1)], front['h'])


    def test_block_conflict(self):
        com_key = default_eccrypto.generate_key(u"curve25519").pub().key_to_hash()
        block = TestBlock(com_id=com_key, links={(1, '1234')})
        db = MockDatabase()
        db.add_block(block)
        front = db.get_frontier(com_key)
        # Frontier should contain seq_num=2
        self.assertEqual(True, [2 in tuples for tuples in front['v']][0])
        # Frontier should indicate holes
        self.assertEqual([(1, 1)], front['h'])


    def test_community_conflict(self):
        # TODO: TBA
        com_key = default_eccrypto.generate_key(u"curve25519").pub().key_to_hash()
        block = TestBlock(com_id=com_key, links={(1, '1234')})
        db = MockDatabase()
        db.add_block(block)
        front = db.get_frontier(com_key)
        # Frontier should contain seq_num=2
        self.assertEqual(True, [2 in tuples for tuples in front['v']][0])
        # Frontier should indicate holes
        self.assertEqual([(1, 1)], front['h'])

    def test_iter(self):
        """
        Check that the iterator of a Block has all of the required keys without duplicates.
        """
        block = TestBlock()
        block_keys = []
        for field in iter(block):
            block_keys.append(field[0])
        expected_keys = set(NoodleBlock.Data._fields)
        # Check if we have the required keys
        self.assertSetEqual(expected_keys | {'hash'}, set(block_keys))
        # Check for duplicates
        self.assertEqual(len(block_keys) - 1, len(expected_keys))
        self.assertEqual(dict(block)['transaction']['id'], 42)

    def test_hash_function(self):
        """
        Check if the hash() function returns the Block hash.
        """
        block = TestBlock()

        self.assertEqual(block.__hash__(), block.hash)
