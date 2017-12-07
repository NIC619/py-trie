from trie.constants import (
    NODE_TYPE_BLANK,
    NODE_TYPE_LEAF,
    NODE_TYPE_EXTENSION,
    NODE_TYPE_BRANCH,
    BLANK_NODE,
    KV_TYPE,
    BRANCH_TYPE,
    LEAF_TYPE,
)
from trie.exceptions import (
    InvalidNode,
)
from trie.utils.binaries import (
    encode_from_bin_keypath,
    decode_to_bin_keypath,
)
from trie.validation import (
    validate_length,
)

from .nibbles import (
    decode_nibbles,
    encode_nibbles,
    is_nibbles_terminated,
    add_nibbles_terminator,
    remove_nibbles_terminator,
)


def get_node_type(node):
    if node == BLANK_NODE:
        return NODE_TYPE_BLANK
    elif len(node) == 2:
        key, _ = node
        nibbles = decode_nibbles(key)
        if is_nibbles_terminated(nibbles):
            return NODE_TYPE_LEAF
        else:
            return NODE_TYPE_EXTENSION
    elif len(node) == 17:
        return NODE_TYPE_BRANCH
    else:
        raise InvalidNode("Unable to determine node type")


def is_blank_node(node):
    return node == BLANK_NODE


def is_leaf_node(node):
    if len(node) != 2:
        return False
    key, _ = node
    nibbles = decode_nibbles(key)
    return is_nibbles_terminated(nibbles)


def is_extension_node(node):
    if len(node) != 2:
        return False
    key, _ = node
    nibbles = decode_nibbles(key)
    return not is_nibbles_terminated(nibbles)


def is_branch_node(node):
    return len(node) == 17


def extract_key(node):
    prefixed_key, _ = node
    key = remove_nibbles_terminator(decode_nibbles(prefixed_key))
    return key


def compute_leaf_key(nibbles):
    return encode_nibbles(add_nibbles_terminator(nibbles))


def compute_extension_key(nibbles):
    return encode_nibbles(nibbles)


def get_common_prefix_length(left_key, right_key):
    for idx, (left_nibble, right_nibble) in enumerate(zip(left_key, right_key)):
        if left_nibble != right_nibble:
            return idx
    return min(len(left_key), len(right_key))


def consume_common_prefix(left_key, right_key):
    common_prefix_length = get_common_prefix_length(left_key, right_key)
    common_prefix = left_key[:common_prefix_length]
    left_remainder = left_key[common_prefix_length:]
    right_remainder = right_key[common_prefix_length:]
    return common_prefix, left_remainder, right_remainder


def key_starts_with(full_key, partial_key):
    return all(left == right for left, right in zip(full_key, partial_key))


# Binary Trie node utils
def parse_node(node):
    """
    Input: a serialized node
    """
    if node[0] == BRANCH_TYPE:
        # Output: left child, right child, node type
        return node[1:33], node[33:], BRANCH_TYPE
    elif node[0] == KV_TYPE:
        # Output: keypath: child, node type
        return decode_to_bin_keypath(node[1:-32]), node[-32:], KV_TYPE
    elif node[0] == LEAF_TYPE:
        # Output: None, value, node type
        return None, node[1:], LEAF_TYPE
    else:
        raise InvalidNode("Unable to parse node")


def encode_kv_node(keypath, node):
    """
    Serializes a key/value node
    """
    assert keypath
    validate_length(node, 32)
    return bytes([KV_TYPE]) + encode_from_bin_keypath(keypath) + node


def encode_branch_node(left_node, right_node):
    """
    Serializes a branch node (ie. a node with 2 children)
    """
    validate_length(left_node, 32)
    validate_length(right_node, 32)
    return bytes([BRANCH_TYPE]) + left_node + right_node


def encode_leaf_node(value):
    """
    Serializes a leaf node
    """
    return bytes([LEAF_TYPE]) + value
