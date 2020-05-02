import random
import hashlib

def sha256_2_string(string_to_hash):
    """ Returns the SHA256^2 hash of a given string input
    in hexadecimal format.

    Args:
        string_to_hash (str): Input string to hash twice

    Returns:
        str: Output of double-SHA256 encoded as hexadecimal string.
    """

    # (hint): feed binary data directly between the two SHA256 rounds
    encoded_str = string_to_hash.encode('utf-8')
    hash_once = hashlib.sha256(encoded_str).digest()
    hash_twice = hashlib.sha256(hash_once).hexdigest()
    return hash_twice

    #return "deadbeef" + hex(int(random.random() * 10000000))[2:]

def encode_as_str(list_to_encode, sep = "|"):
    """ Encodes a list as a string with given separator.

    Args:
        list_to_encode (:obj:`list` of :obj:`Object`): List of objects to convert to strings.
        sep (str, optional): Separator to join objects with.
    """
    return sep.join([str(x) for x in list_to_encode])

def nonempty_intersection(list1, list2):
    """ Returns true iff two lists have a nonempty intersection. """
    return len(list(set(list1) & set(list2))) > 0
