from ipv8.attestation.backbone.datastore.utils import key_to_id


class Chain:
    """
    Index class for chain to ensure that each peer will converge into a consistent chain log.
    """

    def __init__(self):
        self.chain = dict()
        self.holes = set()

        self.inconsistencies = dict()
        self.terminal = set()

        self.forward_pointers = dict()
        self.frontier = dict()

    def ranges(self, nums):
        nums = sorted(nums)
        gaps = [[s, e] for s, e in zip(nums, nums[1:]) if s + 1 < e]
        edges = iter(nums[:1] + sum(gaps, []) + nums[-1:])
        return list(zip(edges, edges))

    def calc_terminal(self, current):
        terminal = set()
        for s, h in current:
            if (s, h) not in self.forward_pointers:
                terminal.add((s, h))
            else:
                # make a bfs step
                terminal.update(self.calc_terminal(self.forward_pointers[(s, h)]))
        return terminal

    def add_inconsistency(self, seq_num, exp_hash):
        if seq_num not in self.inconsistencies:
            self.inconsistencies[seq_num] = set()
        self.inconsistencies[seq_num].add(exp_hash)

    def update_frontiers(self, block):

        # New block received
        # 1. Does it fix some known holes?
        if block.sequence_number in self.holes:
            self.holes.remove(block.sequence_number)

        # 2. Does it introduce new holes?
        for seq_num, block_hash in block.previous:
            if seq_num not in self.chain:
                while seq_num not in self.chain and seq_num >= 1:
                    self.holes.add(seq_num)
                    seq_num -= 1

        # 3. Does it change terminal nodes?
        self.terminal = self.calc_terminal(self.terminal)
        current = {(block.sequence_number, key_to_id(block.hash))}
        self.terminal.update(self.calc_terminal(current))

        # Update frontier with holes, inconsistencies and terminal
        self.frontier['v'] = self.terminal
        self.frontier['h'] = self.ranges(self.holes)
        self.frontier['i'] = self.inconsistencies

    def add_block(self, block):
        if block.sequence_number not in self.chain:
            # new sequence number
            self.chain[block.sequence_number] = set()

        self.chain[block.sequence_number].add(key_to_id(block.hash))
        # analyze back pointers: block.previous
        for seq_num, block_hash in block.previous:
            if (seq_num, block_hash) not in self.forward_pointers:
                self.forward_pointers[(seq_num, block_hash)] = set()
            self.forward_pointers[(seq_num, block_hash)].add((block.sequence_number, key_to_id(block.hash)))

            if seq_num in self.chain and block_hash not in self.chain[seq_num]:
                # previous block not present, but sibling is present => inconsistency
                self.add_inconsistency(seq_num, block_hash)

        # analyze forward pointers, i.e. inconsistencies
        if block.sequence_number in self.inconsistencies and key_to_id(block.hash) in self.inconsistencies[block.sequence_number]:
            # There exits a block that links to this => inconsistency fixed
            self.inconsistencies[block.sequence_number].remove(key_to_id(block.hash))
            if not self.inconsistencies[block.sequence_number]:
                del self.inconsistencies[block.sequence_number]

        self.update_frontiers(block)
