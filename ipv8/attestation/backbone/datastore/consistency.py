from ipv8.attestation.backbone.datastore.utils import key_to_id, ranges, expand_ranges


class ChainState:
    """
    Class to collapse the chain and validate on integrity of invariants
    """

    def __init__(self):
        self.state = dict()

    def add_block(self, block):
        # Update the state
        pass

    def is_valid(self):
        pass

    def get_state(self):
        return self.state


class Chain:
    """
    Index class for chain to ensure that each peer will converge into a consistent chain log.
    """

    def __init__(self, chain_id, personal=True, num_frontiers_store=50):
        self.chain = dict()
        self.holes = set()

        self.chain_id = chain_id

        self.inconsistencies = set()
        self.terminal = set()

        self.personal = personal
        self.forward_pointers = dict()
        self.frontier = {'p': personal}

        self.states = dict()
        self.state_votes = dict()
        self.num_front_store = num_frontiers_store

    def is_state_consistent(self):
        """
        State should be 'consistent' if there no known holes and inconsistencies
        """
        return not self.inconsistencies and not self.holes

    def add_state(self, state_name, chain_state):
        self.states[state_name] = chain_state

    def add_audit_proof(self):
        pass

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
        self.inconsistencies.add((seq_num, exp_hash))

    def _update_frontiers(self, block_links, block_seq_num, block_hash):

        # New block received
        # 1. Does it fix some known holes?
        if block_seq_num in self.holes:
            self.holes.remove(block_seq_num)

        # 2. Does it introduce new holes?
        for s, h in block_links:
            if s not in self.chain:
                while s not in self.chain and s >= 1:
                    self.holes.add(s)
                    s -= 1

        # 3. Does it change terminal nodes?
        self.terminal = self.calc_terminal(self.terminal)
        current = {(block_seq_num, block_hash)}
        self.terminal.update(self.calc_terminal(current))

        # Update frontier with holes, inconsistencies and terminal
        self.frontier['v'] = self.terminal
        self.frontier['h'] = ranges(self.holes)
        self.frontier['i'] = self.inconsistencies

    def max_known_seq_num(self):
        return max(self.chain) if self.chain else 0

    def clean_up_state_votes(self):
        current_front = max(self.frontier['v'])[0]
        for k in list(self.state_votes.keys()):
            if current_front - max(k)[0] > self.num_front_store:
                del self.state_votes[k]

    def get_latest_max_votes(self):
        return max(self.state_votes.items(), key=lambda x: len(x[1]))

    def get_latest_votes(self):
        return max(self.state_votes.items(), key=lambda x: max(x[0])[0])

    def reconcile(self, front):
        if 'state' in front:
            # persist state val
            key = tuple(front['v'])
            if key not in self.state_votes:
                self.state_votes[key] = set()
            # TODO: periodically clean this:
            self.state_votes[key].add(front['state'])

        f_holes = expand_ranges(front['h']) if 'h' in front and front['h'] else set()
        max_front_seq = max(front['v'])[0] if 'v' in front and front['v'] else 0

        front_known_seq = expand_ranges([(1, max_front_seq)]) - f_holes
        peer_known_seq = expand_ranges([(1, self.max_known_seq_num())]) - self.holes

        # Front has blocks that peer is missing => Request from front these blocks
        f_diff = front_known_seq - peer_known_seq
        front_diff = {'m': ranges(f_diff)}

        if 'v' in front:
            # Front has blocks with conflicting hash => Request these blocks
            front_diff['c'] = {(s, h) for s, h in front['v'] if s in self.chain and h not in self.chain[s]}

        for i in self.inconsistencies:
            for t in self.calc_terminal([i]):
                if t in front['v'] and t not in front['i'] and t[0] not in front['h']:
                    front_diff['c'].add(i)

        return front_diff, None

    def add_block(self, block):
        block_links = block.previous if self.personal else block.links
        block_seq_num = block.sequence_number if self.personal else block.com_seq_num
        block_hash = key_to_id(block.hash)

        if block_seq_num not in self.chain:
            # new sequence number
            self.chain[block_seq_num] = set()

        self.chain[block_seq_num].add(block_hash)

        # analyze back pointers
        for s, h in block_links:
            if (s, h) not in self.forward_pointers:
                self.forward_pointers[(s, h)] = set()
            self.forward_pointers[(s, h)].add((block_seq_num, block_hash))

            if s in self.chain and h not in self.chain[s]:
                # previous block not present, but sibling is present => inconsistency
                self.add_inconsistency(s, h)

        # analyze forward pointers, i.e. inconsistencies
        if (block_seq_num, block_hash) in self.inconsistencies:
            # There exits a block that links to this => inconsistency fixed
            self.inconsistencies.remove((block_seq_num, block_hash))

        self._update_frontiers(block_links, block_seq_num, block_hash)

        # Update all states
        for s in self.states.values():
            s.add_block(block)
