from __future__ import absolute_import

import time
from binascii import hexlify

from ..trustchain.block import TrustChainBlock
from ..trustchain.block import EMPTY_PK, EMPTY_SIG, GENESIS_SEQ, GENESIS_HASH, UNKNOWN_SEQ

from ...messaging.serialization import default_serializer
from ...keyvault.crypto import default_eccrypto
from ...util import old_round

from six import binary_type

import orjson as json


class NoodleBlock(TrustChainBlock):
    """
    Differences between the NoodleBlock and the "regular" TrustChainBlock:
    - NoodleBlock uses orjson for serialization.
    """

    def __init__(self, data=None, serializer=default_serializer):
        """
        Create a new NoodleBlock or load a NoodleBlock from an existing database entry.

        :param data: Optional data to initialize this block with.
        :type data: TrustChainBlock.Data or list
        :param serializer: An optional custom serializer to use for this block.
        :type serializer: Serializer
        """
        super(TrustChainBlock, self).__init__()
        self.serializer = serializer
        if data is None:
            # data
            self.type = b'unknown'
            self.transaction = {}
            self._transaction = json.dumps({})
            # identity
            self.public_key = EMPTY_PK
            self.sequence_number = GENESIS_SEQ
            # linked identity
            self.link_public_key = EMPTY_PK
            self.link_sequence_number = UNKNOWN_SEQ
            # validation
            self.previous_hash = GENESIS_HASH
            self.signature = EMPTY_SIG
            self.timestamp = int(old_round(time.time() * 1000))
            # debug stuff
            self.insert_time = None
        else:
            self._transaction = data[1] if isinstance(data[1], bytes) else binary_type(data[1])
            self.transaction = json.loads(self._transaction)
            (self.type, self.public_key, self.sequence_number, self.link_public_key, self.link_sequence_number,
             self.previous_hash, self.signature, self.timestamp, self.insert_time) = (data[0], data[2], data[3],
                                                                                      data[4], data[5], data[6],
                                                                                      data[7], data[8], data[9])
            self.type = self.type if isinstance(self.type, bytes) else str(self.type).encode('utf-8')
            self.public_key = self.public_key if isinstance(self.public_key, bytes) else binary_type(self.public_key)
            self.link_public_key = (self.link_public_key if isinstance(self.link_public_key, bytes)
                                    else binary_type(self.link_public_key))
            self.previous_hash = (self.previous_hash if isinstance(self.previous_hash, bytes)
                                  else binary_type(self.previous_hash))
            self.signature = self.signature if isinstance(self.signature, bytes) else binary_type(self.signature)
        self.hash = self.calculate_hash()
        self.crypto = default_eccrypto

    def __iter__(self):
        """
        This override allows one to take the dict(<block>) of a block.
        :return: generator to iterate over all properties of this block
        """
        for key, value in self.__dict__.items():
            if key == 'key' or key == 'serializer' or key == 'crypto' or key == '_transaction':
                continue
            if key == 'transaction':
                yield key, json.loads(self._transaction)[1]
            elif isinstance(value, binary_type) and key != "insert_time" and key != "type":
                yield key, hexlify(value).decode('utf-8')
            else:
                yield key, value.decode('utf-8') if isinstance(value, binary_type) else value
