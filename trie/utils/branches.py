from eth_utils import (
    encode_hex,
)

from trie.bin_trie import (
    BinaryTrie,
)
from trie.constants import (
    BLANK_HASH,
    KV_TYPE,
    BRANCH_TYPE,
    LEAF_TYPE,
    BYTE_0,
    BYTE_1,
)
from trie.utils.sha3 import (
    keccak,
)
from trie.utils.binaries import (
    decode_from_bin,
    encode_from_bin_keypath,
    decode_to_bin_keypath,
)
from trie.utils.nodes import (
    parse_node,
    encode_kv_node,
    encode_branch_node,
)

def get_long_format_branch(db, node_hash, keypath):
    """
    Get a long-format Merkle branch
    """
    if node_hash == BLANK_HASH:
        return []
    if not keypath:
        return [db[node_hash]]
    left_child, right_child, nodetype = parse_node(db[node_hash])
    if nodetype == KV_TYPE:
        if keypath[:len(left_child)] == left_child:
            return [db[node_hash]] + get_long_format_branch(db, right_child, keypath[len(left_child):])
        else:
            return [db[node_hash]]
    elif nodetype == BRANCH_TYPE:
        if keypath[:1] == BYTE_0:
            return [db[node_hash]] + get_long_format_branch(db, left_child, keypath[1:])
        else:
            return [db[node_hash]] + get_long_format_branch(db, right_child, keypath[1:])

def verify_long_format_branch(branch, root, keypath, value):
    db = {keccak(node): node for node in branch}
    assert BinaryTrie(db=db, root_hash=root).get(keypath) == value
    return True


def get_subtrie(db, node_hash):
    """
    Get full subtrie of a given node
    """
    if node_hash == BLANK_HASH:
        return []
    node = db[node_hash]
    left_child, right_child, nodetype = parse_node(node)
    if nodetype == KV_TYPE:
        return [node] + get_subtrie(db, right_child)
    elif nodetype == BRANCH_TYPE:
        return [node] + get_subtrie(db, left_child) + get_subtrie(db, right_child)
    elif nodetype == LEAF_TYPE:
        return [node]

def get_prefix_witness(db, node_hash, keypath):
    """
    Get all witness given a keypath prefix.
    Include 
    
    1. witness along the keypath and 
    2. witness in the subtrie of the last node in keypath
    """
    if node_hash == BLANK_HASH:
        return []
    node = db[node_hash]
    if not keypath:
        return get_subtrie(db, node_hash)
    left_child, right_child, nodetype = parse_node(node)
    if nodetype == KV_TYPE:
        if len(keypath) < len(left_child) and left_child[:len(keypath)] == keypath:
            return [node] + get_subtrie(db, right_child)
        if keypath[:len(left_child)] == left_child:
            return [node] + get_prefix_witness(db, right_child, keypath[len(left_child):])
        else:
            return [node]
    elif nodetype == BRANCH_TYPE:
        if keypath[:1] == BYTE_0:
            return [node] + get_prefix_witness(db, left_child, keypath[1:])
        else:
            return [node] + get_prefix_witness(db, right_child, keypath[1:])


def get_branch(db, node_hash, keypath):
    """
    Get a Merkle proof given a keypath
    """
    if node_hash == BLANK_HASH:
        return []
    if not keypath:
        return [db[node_hash]]
    left_child, right_child, nodetype = parse_node(db[node_hash])
    if nodetype == KV_TYPE:
        path = encode_from_bin_keypath(left_child)
        if keypath[:len(left_child)] == left_child:
            return [b'\x01'+path] + get_branch(db, right_child, keypath[len(left_child):])
        else:
            return [b'\x01'+path, db.get(right_child)]
    elif nodetype == BRANCH_TYPE:
        if keypath[:1] == BYTE_0:
            return [b'\x02'+right_child] + get_branch(db, left_child, keypath[1:])
        else:
            return [b'\x03'+left_child] + get_branch(db, right_child, keypath[1:])

# Verify a Merkle proof
def verify_branch(branch, root, keypath, value):
    nodes = [branch[-1]]
    _keypath = b''
    for data in branch[-2::-1]:
        marker, node = data[0], data[1:]
        # it's a keypath
        if marker == 1:
            node = decode_to_bin_keypath(node)
            _keypath = node + _keypath
            nodes.insert(0, encode_kv_node(node, keccak(nodes[0])))
        # it's a right-side branch
        elif marker == 2:
            _keypath = BYTE_0 + _keypath
            nodes.insert(0, encode_branch_node(keccak(nodes[0]), node))
        # it's a left-side branch
        elif marker == 3:
            _keypath = BYTE_1 + _keypath
            nodes.insert(0, encode_branch_node(node, keccak(nodes[0])))
        else:
            raise Exception("Foo")
    if value:
        assert _keypath == keypath
    assert keccak(nodes[0]) == root
    db = {keccak(node): node for node in nodes}
    assert BinaryTrie(db=db, root_hash=root).get(keypath) == value
    return True


def check_bintrie_invariants(db, node):
    if node == BLANK_HASH:
        return
    left_child, right_child, nodetype = parse_node(db[node])
    if nodetype == LEAF_TYPE:
        return
    elif nodetype == KV_TYPE:
        # (k1, (k2, node)) two nested key values nodes not allowed
        _, sub_right_child, subnodetype = parse_node(db[right_child])
        assert subnodetype != KV_TYPE
        # Childre of a key node cannot be empty
        assert sub_right_child != BLANK_HASH
        check_bintrie_invariants(db, right_child)
        return
    else:
        # Children of a branch node cannot be empty
        assert left_child != BLANK_HASH and right_child != BLANK_HASH
        check_bintrie_invariants(db, left_child)
        check_bintrie_invariants(db, right_child)


def print_nodes(db, node, prefix=b'', output_to_console=False):
    """
    Pretty-print all nodes in a tree (for debugging purposes)
    """
    if node == BLANK_HASH:
        if output_to_console:
            print('empty node')
        return {}
    left_child, right_child, nodetype = parse_node(db[node])
    if nodetype == LEAF_TYPE:
        if output_to_console:
            print('value node', encode_hex(node[:4]), right_child)
        return {prefix: right_child}
    elif nodetype == KV_TYPE:
        if output_to_console:
            print(('kv node:', encode_hex(node[:4]), ''.join(['1' if x == 1 else '0' for x in left_child]), encode_hex(right_child[:4])))
        print_nodes(db, right_child, prefix + left_child)
    else:
        if output_to_console:
            print(('branch node:', encode_hex(node[:4]), encode_hex(left_child[:4]), encode_hex(right_child[:4])))
        output = {}
        output.update(print_nodes(db, left_child, prefix + BYTE_0))
        output.update(print_nodes(db, right_child, prefix + BYTE_1))
        return output
