from abc import ABC, abstractmethod # We want to make Block an abstract class; either a PoW or PoA block
import blockchain
from blockchain.util import sha256_2_string, encode_as_str
import time
import persistent
from blockchain.util import nonempty_intersection

class Block(ABC, persistent.Persistent):

    def __init__(self, height, transactions, parent_hash, is_genesis=False, include_merkle_root=True):
        """ Creates a block template (unsealed).

        Args:
            height (int): height of the block in the chain (# of blocks between block and genesis).
            transactions (:obj:`list` of :obj:`Transaction`): ordered list of transactions in the block.
            parent_hash (str): the hash of the parent block in the blockchain.
            is_genesis (bool, optional): True only if the block is a genesis block.

        Attributes:
            parent_hash (str): the hash of the parent block in blockchain.
            height (int): height of the block in the chain (# of blocks between block and genesis).
            transactions (:obj:`list` of :obj:`Transaction`): ordered list of transactions in the block.
            timestamp (int): Unix timestamp of the block.
            target (int): Target value for the block's seal to be valid (different for each seal mechanism)
            is_genesis (bool): True only if the block is a genesis block (first block in the chain).
            merkle (str): Merkle hash of the list of transactions in a block, uniquely identifying the list.
            seal_data (int): Seal data for block (in PoW this is the nonce satisfying the PoW puzzle; in PoA, the signature of the authority").
            hash (str): Hex-encoded SHA256^2 hash of the block header (self.header()).
        """
        self.parent_hash = parent_hash
        self.height = height
        self.transactions = transactions
        self.timestamp = int(time.time())
        self.target = self.calculate_appropriate_target()
        self.is_genesis = is_genesis
        
        if include_merkle_root:
            self.merkle = self.calculate_merkle_root()
        else:
            self.merkle = sha256_2_string("".join([str(x) for x in self.transactions]))

        self.seal_data = 0 # temporarily set seal_data to 0
        self.hash = self.calculate_hash() # keep track of hash for caching purposes

    def calculate_merkle_root(self):
        """ Gets the Merkle root hash for a given list of transactions.

        This method is incomplete!  Right now, it only hashes the
        transactions together, which does not enable the same type
        of lite client support a true Merkle hash would.

        Follow the description in the problem sheet to calculte the merkle root. 
        If there is no transaction, return SHA256(SHA256("")).
        If there is only one transaction, the merkle root is the transaction hash.
        For simplicity, when computing H(AB) = SHA256(SHA256(H(A) + H(B))), directly double-hash the hex string of H(A) concatenated with H(B).
        E.g., H(A) = 0x10, H(B) = 0xff, then H(AB) = SHA256(SHA256("10ff")).

        Returns:
            str: Merkle root hash of the list of transactions in a block, uniquely identifying the list.
        """
        hash_txs = list()
        for x in self.transactions:
            hash_txs.append(sha256_2_string(str(x)))

        if len(hash_txs) == 0:
            hash_txs = sha256_2_string("")
        
        while len(hash_txs) > 1:
            i = 0
            nxt_tx = list()

            while i < len(hash_txs):
                if i != len(hash_txs) - 1:
                    nxt_two_txs = hash_txs[i] + hash_txs[i+1]
                    nxt_tx.append(sha256_2_string(nxt_two_txs))
                    i = i + 2
                else:
                    nxt_tx.append(hash_txs[i])
                    i = i + 1
            
            hash_txs = nxt_tx
        
        return hash_txs[0]

    def unsealed_header(self):
        """ Computes the header string of a block (the component that is sealed by mining).

        Returns:
            str: String representation of the block header without the seal.
        """
        return encode_as_str([self.height, self.timestamp, self.target, self.parent_hash, self.is_genesis, self.merkle], sep='`')

    def header(self):
        """ Computes the full header string of a block after mining (includes the seal).

        Returns:
            str: String representation of the block header.
        """
        return encode_as_str([self.unsealed_header(), self.seal_data], sep='`')

    def calculate_hash(self):
        """ Get the SHA256^2 hash of the block header.

        Returns:
            str: Hex-encoded SHA256^2 hash of self.header()
        """
        return sha256_2_string(str(self.header()))

    def __repr__(self):
        """ Get a full representation of a block as string, for debugging purposes; includes all transactions.

        Returns:
            str: Full and unique representation of a block and its transactions.
        """
        return encode_as_str([self.header(), "!".join([str(tx) for tx in self.transactions])], sep="`")

    def set_seal_data(self, seal_data):
        """ Adds seal data to a block, recomputing the block's hash for its changed header representation.
        This method should never be called after a block is added to the blockchain!

        Args:
            seal_data (int): The seal data to set.
        """
        self.seal_data = seal_data
        self.hash = self.calculate_hash()

    def is_valid(self):
        """ Check whether block is fully valid according to block rules.

        Includes checking for no double spend, that all transactions are valid, that all header fields are correctly
        computed, etc.

        Returns:
            bool, str: True if block is valid, False otherwise plus an error or success message.
        """

        chain = blockchain.chain # This object of type Blockchain may be useful

        # (checks that apply to all blocks)
        # Check that Merkle root calculation is consistent with transactions in block (use the calculate_merkle_root function) [test_rejects_invalid_merkle]
        # On failure: return False, "Merkle root failed to match"
        if self.merkle != self.calculate_merkle_root():
            return False, "Merkle root failed to match"

        # Check that block.hash is correctly calculated [test_rejects_invalid_hash]
        # On failure: return False, "Hash failed to match"
        string_header = str(self.header())
        if self.hash != sha256_2_string(string_header):
            return False, "Hash failed to match"

        # Check that there are at most 900 transactions in the block [test_rejects_too_many_txs]
        # On failure: return False, "Too many transactions"
        if len(self.transactions) > 900:
            return False, "Too many transactions"

        # (checks that apply to genesis block)
            # Check that height is 0 and parent_hash is "genesis" [test_invalid_genesis]
            # On failure: return False, "Invalid genesis"
        if (self.height == 0):
            #if not chain.blocks[self.parent_hash].is_genesis:
            if (self.parent_hash != "genesis"):
                return False, "Invalid genesis"
        
        if (self.height != 0):
            #if chain.blocks[self.parent_hash].is_genesis:
            if (self.parent_hash == "genesis"):
                return False, "Invalid genesis"

        # (checks that apply only to non-genesis blocks)
            # Check that parent exists (you may find chain.blocks helpful) [test_nonexistent_parent]
            # On failure: return False, "Nonexistent parent"
        if self.parent_hash != "genesis" and self.height != 0:
            if self.parent_hash not in chain.blocks:
                return False, "Nonexistent parent"

            # Check that height is correct w.r.t. parent height [test_bad_height]
            # On failure: return False, "Invalid height"
            parent_height = chain.blocks[self.parent_hash].height
            if self.height != (parent_height + 1):
                return False, "Invalid height"

            # Check that timestamp is non-decreasing [test_bad_timestamp]
            # On failure: return False, "Invalid timestamp"
            parent_timestamp = chain.blocks[self.parent_hash].timestamp
            if self.timestamp < parent_timestamp:
                return False, "Invalid timestamp"

            # Check that seal is correctly computed and satisfies "target" requirements; use the provided seal_is_valid method [test_bad_seal]
            # On failure: return False, "Invalid seal"
            if not self.seal_is_valid():
                return False, "Invalid seal"

            # Check that all transactions within are valid (use tx.is_valid) [test_malformed_txs]
            # On failure: return False, "Malformed transaction included"
            for tx in self.transactions:
                if not tx.is_valid():
                    return False, "Malformed transaction included"

            # Check that for every transaction
                # the transaction has not already been included on a block on the same blockchain as this block [test_double_tx_inclusion_same_chain]
                # (or twice in this block; you will have to check this manually) [test_double_tx_inclusion_same_block]
                # (you may find chain.get_chain_ending_with and chain.blocks_containing_tx and util.nonempty_intersection useful)
                # On failure: return False, "Double transaction inclusion"
            
            tx_dict = {}
            for tx in self.transactions:
                if (tx.hash in chain.blocks_containing_tx):
                    return False, "Double transaction inclusion"
                
                if tx.hash not in tx_dict:
                    tx_dict[tx.hash] = tx
            
            lst_Length = len(self.transactions)
            set_Length = len(set(self.transactions))
            
            if lst_Length != set_Length:
                return False, "Double transaction inclusion"
            
            txs_in_block = {}
            inputs_spent_in_block = list()
            for tx in self.transactions:
                inp = 0

                for inp_ref in tx.input_refs:
                    inp_ref_split = inp_ref.split(':')
                    tx_hash = inp_ref_split[0]
                    idx = int(inp_ref_split[1])

                    if tx_hash not in chain.all_transactions:
                        if tx_hash not in tx_dict:
                            return False, "Required output not found"
                    
                    if tx_hash in chain.all_transactions:
                        all_Outputs = chain.all_transactions[tx_hash].outputs
                        if idx >= len(all_Outputs):
                            return False, "Required output not found"
                        else:
                            input_tran = all_Outputs[idx]
                    
                    if tx_hash in tx_dict:
                        tx_Outputs = tx_dict[tx_hash].outputs
                        if idx >= len(tx_Outputs):
                            return False, "Required output not found"
                        else:
                            input_tran = tx_Outputs[idx]
                    
                    inp = inp + input_tran.amount
                    receiver = input_tran.receiver
                    senderList = list()
                    for user in tx.outputs:
                        senderList.append(user.sender)

                    for user in senderList:
                        if user != receiver:
                            return False, "User inconsistencies"
                    
                    if tx_hash in chain.blocks_containing_tx and not nonempty_intersection(chain.blocks_containing_tx[tx_hash], chain.get_chain_ending_with(self.parent_hash)):
                        return False, "Input transaction not found"
                                        
                    get_blocks_with_input_intersection = list()
                    get_blocks_with_txs_intersection = list()

                    blocks_in_chain = chain.get_chain_ending_with(self.parent_hash)
                    blocks_with_input = chain.blocks_spending_input.get(inp_ref, get_blocks_with_input_intersection)
                    blocks_with_txs = chain.blocks_containing_tx.get(tx_hash, get_blocks_with_txs_intersection)
                    
                    if nonempty_intersection(blocks_in_chain, blocks_with_input):
                        return False, "Double-spent input"
                    
                    if inp_ref in inputs_spent_in_block:
                        return False, "Double-spent input"
                    
                    if nonempty_intersection(blocks_in_chain, blocks_with_txs) or tx_hash in txs_in_block:
                        inputs_spent_in_block.append(inp_ref)
                
                out = 0
                for output in tx.outputs:
                    out = out + output.amount
                
                if out > inp:
                    return False, "Creating money"
                txs_in_block[tx.hash] = tx

        return True, "All checks passed"


    # ( these just establish methods for subclasses to implement; no need to modify )
    @abstractmethod
    def get_weight(self):
        """ Should be implemented by subclasses; gives consensus weight of block. """
        pass

    @abstractmethod
    def calculate_appropriate_target(self):
        """ Should be implemented by subclasses; calculates correct target to use in block. """
        pass

    @abstractmethod
    def seal_is_valid(self):
        """ Should be implemented by subclasses; returns True iff the seal_data creates a valid seal on the block. """
        pass
