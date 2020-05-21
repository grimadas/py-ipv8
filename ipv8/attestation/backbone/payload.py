from ...messaging.payload import Payload


class BlockPayload(Payload):
    """
    Payload for message that ships a signed block
    """

    format_list = ['varlenI', 'varlenI', '74s', 'I', 'varlenI', 'varlenI', '74s', 'I', '64s', 'Q']

    def __init__(self, block_type, transaction, public_key, sequence_number,
                 previous, links, com_id, com_seq_num, signature, timestamp):
        super(BlockPayload, self).__init__()
        self.type = block_type
        self.transaction = transaction
        self.public_key = public_key
        self.sequence_number = sequence_number
        self.previous = previous
        self.links = links
        self.com_id = com_id
        self.com_seq_num = com_seq_num
        self.signature = signature
        self.timestamp = timestamp

    @classmethod
    def from_block(cls, block):
        return BlockPayload(
            block.type,
            block._transaction,
            block.public_key,
            block.sequence_number,
            block._previous,
            block._links,
            block.com_id,
            block.com_seq_num,
            block.signature,
            block.timestamp)

    def to_pack_list(self):
        data = [('varlenI', self.type),
                ('varlenI', self.transaction),
                ('74s', self.public_key),
                ('I', self.sequence_number),
                ('varlenI', self.previous),
                ('varlenI', self.links),
                ('74s', self.com_id),
                ('I', self.com_seq_num),
                ('64s', self.signature),
                ('Q', self.timestamp)]

        return data

    @classmethod
    def from_unpack_list(cls, *args):
        return BlockPayload(*args)


class BlockBroadcastPayload(BlockPayload):
    """
    Payload for a message that contains a half block and a TTL field for broadcasts.
    """

    format_list = ['varlenI', 'varlenI', '74s', 'I', 'varlenI', 'varlenI', '74s', 'I', '64s', 'Q', 'I']

    def __init__(self, block_type, transaction, public_key, sequence_number,
                 previous, links, com_id, com_seq_num, signature, timestamp, ttl):
        super(BlockBroadcastPayload, self).__init__(block_type, transaction, public_key, sequence_number,
                                                    previous, links, com_id, com_seq_num, signature, timestamp)
        self.ttl = ttl

    @classmethod
    def from_block_gossip(cls, block, ttl):
        return BlockBroadcastPayload(
            block.type,
            block._transaction,
            block.public_key,
            block.sequence_number,
            block._previous,
            block._links,
            block.com_id,
            block.com_seq_num,
            block.signature,
            block.timestamp,
            ttl
        )

    def to_pack_list(self):
        data = super(BlockBroadcastPayload, self).to_pack_list()
        data.append(('I', self.ttl))
        return data

    @classmethod
    def from_unpack_list(cls, *args):
        return BlockBroadcastPayload(*args)


class KVPayload(Payload):
    format_list = ['varlenI', 'varlenI']

    def __init__(self, key, value):
        Payload.__init__(self)
        self.key = key
        self.value = value

    def to_pack_list(self):
        return [('varlenI', self.key), ('varlenI', self.value)]

    @classmethod
    def from_unpack_list(cls, key, value):
        return KVPayload(key, value)


class SubscriptionsPayload(KVPayload):
    pass


class FrontierPayload(KVPayload):
    pass


class BlocksRequestPayload(KVPayload):
    pass


class BlockResponsePayload(KVPayload):
    pass


class StateRequestPayload(KVPayload):
    pass


class StateResponsePayload(KVPayload):
    pass


class AuditRequestPayload(KVPayload):
    pass


class AuditProofPayload(KVPayload):
    pass


class AuditProofRequestPayload(KVPayload):
    """
    Payload that holds a request for an audit proof.
    """
    pass


class AuditProofResponsePayload(KVPayload):
    """
    Payload that holds the response with an audit proof or chain state.
    """
    pass


class PingPayload(Payload):
    format_list = ['I']

    def __init__(self, identifier):
        super(PingPayload, self).__init__()
        self.identifier = identifier

    def to_pack_list(self):
        return [('I', self.identifier)]

    @classmethod
    def from_unpack_list(cls, identifier):
        return PingPayload(identifier)


class PeerCrawlResponsePayload(Payload):
    """
    Request a crawl that will estimate the balance of a peer that is not older than some seq_num
    """

    format_list = ['Q', 'varlenI']

    def __init__(self, crawl_id, chain):
        super(PeerCrawlResponsePayload, self).__init__()
        self.crawl_id = crawl_id
        self.chain = chain

    def to_pack_list(self):
        data = [('Q', self.crawl_id),
                ('varlenI', self.chain)]

        return data

    @classmethod
    def from_unpack_list(cls, crawl_id, chain):
        return PeerCrawlResponsePayload(crawl_id, chain)


class EmptyCrawlResponsePayload(Payload):
    """
    Payload for the message that indicates that there are no blocks to respond.
    """

    format_list = ['I']

    def __init__(self, crawl_id):
        super(EmptyCrawlResponsePayload, self).__init__()
        self.crawl_id = crawl_id

    def to_pack_list(self):
        data = [('I', self.crawl_id)]
        return data

    @classmethod
    def from_unpack_list(cls, crawl_id):
        return EmptyCrawlResponsePayload(crawl_id)


class CrawlResponsePayload(Payload):
    """
    Payload for the response to a crawl request.
    """

    format_list = ['74s', 'I', '74s', 'I', '32s', '64s', 'varlenI', 'varlenI', 'Q', 'I', 'I', 'I']

    def __init__(self, public_key, sequence_number, link_public_key, link_sequence_number, previous_hash, signature,
                 block_type, transaction, timestamp, crawl_id, cur_count, total_count):
        super(CrawlResponsePayload, self).__init__()
        self.public_key = public_key
        self.sequence_number = sequence_number
        self.link_public_key = link_public_key
        self.link_sequence_number = link_sequence_number
        self.previous_hash = previous_hash
        self.signature = signature
        self.type = block_type
        self.transaction = transaction
        self.timestamp = timestamp
        self.crawl_id = crawl_id
        self.cur_count = cur_count
        self.total_count = total_count

    @classmethod
    def from_crawl(cls, block, crawl_id, cur_count, total_count):
        return CrawlResponsePayload(
            block.public_key,
            block.sequence_number,
            block.link_public_key,
            block.link_sequence_number,
            block.previous_hash,
            block.signature,
            block.type,
            block._transaction,
            block.timestamp,
            crawl_id,
            cur_count,
            total_count,
        )

    def to_pack_list(self):
        data = [('74s', self.public_key),
                ('I', self.sequence_number),
                ('74s', self.link_public_key),
                ('I', self.link_sequence_number),
                ('32s', self.previous_hash),
                ('64s', self.signature),
                ('varlenI', self.type),
                ('varlenI', self.transaction),
                ('Q', self.timestamp),
                ('I', self.crawl_id),
                ('I', self.cur_count),
                ('I', self.total_count)]

        return data

    @classmethod
    def from_unpack_list(cls, *args):
        return CrawlResponsePayload(*args)
