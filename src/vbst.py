import sys
import blst
import hashlib
from poly_utils import PrimeField
from kzg_utils import KzgUtils
from fft import fft
from time import time
from random import randint, shuffle


# General functions

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes(32, "little")


def int_from_bytes(x: bytes) -> int:
    return int.from_bytes(x, "little")


def hash(x):
    if isinstance(x, bytes):
        return hashlib.sha256(x).digest()
    elif isinstance(x, blst.P1):
        return hash(x.compress())
    b = b""
    for a in x:
        if isinstance(a, bytes):
            b += a
        elif isinstance(a, int):
            b += a.to_bytes(32, "little")
        elif isinstance(a, blst.P1):
            b += hash(a.compress())
    return hash(b)


def hash_to_int(x):
    return int.from_bytes(hash(x), "little")


class KzgIntegration:
    def __init__(self, secret: int, modulus: int, width: int, primitive_root: int):
        self.modulus = modulus
        self.width = width
        assert pow(primitive_root, (modulus - 1) // width, modulus) != 1
        assert pow(primitive_root, modulus - 1, modulus) == 1
        self.root_of_unity = pow(
            primitive_root, (modulus - 1) // width, modulus)
        self.setup = self._generate_setup(width, secret)

    def _generate_setup(self, size, secret):
        """
        Generates a setup in the G1 group and G2 group, as well as the Lagrange polynomials in G1 (via FFT)
        """
        g1_setup = [blst.G1().mult(pow(secret, i, self.modulus))
                    for i in range(size)]
        g2_setup = [blst.G2().mult(pow(secret, i, self.modulus))
                    for i in range(size)]
        g1_lagrange = fft(g1_setup, self.modulus, self.root_of_unity, inv=True)
        return {"g1": g1_setup, "g2": g2_setup, "g1_lagrange": g1_lagrange}

    def kzg_utils(self):
        primefield = PrimeField(self.modulus, self.width)
        domain = [pow(self.root_of_unity, i, self.modulus)
                  for i in range(self.width)]
        return KzgUtils(self.modulus, self.width, domain, self.setup, primefield)


class VBSTNode(object):
    def __init__(self, key: bytes, value: bytes):
        self.value = value
        self.key = key
        self.left = None
        self.right = None
        self.hash = None
        self.commitment = None

    def node_hash(self):
        if self.is_leaf():
            self.hash = hash([self.key, self.value])
        else:
            self.hash = hash(
                [self.commitment.compress(), self.key, self.value])

    def is_leaf(self) -> bool:
        return self.left is None and self.right is None


class VBST:
    def __init__(self, kzg: KzgIntegration, root: VBSTNode):
        self.kzg = kzg.kzg_utils()
        self.setup = kzg.setup
        self.root = root
        self.modulus = kzg.modulus

    def _insert(self, node: VBSTNode, key: bytes, value: bytes, update: bool):
        """
        Recursive insert operator
        """

        if node is None:
            return VBSTNode(key, value)

        if key == node.key:
            if update:
                node.value = value
        elif key < node.key:
            node.left = self._insert(node.left, key, value, update)
        elif key > node.key:
            node.right = self._insert(node.right, key, value, update)
        return node

    def insert_node(self, key: bytes, value: bytes, update: bool = False):
        """
        Insert a node into the tree
        """
        self.root = self._insert(self.root, key, value, update)

    def upsert_vc_node(self, key: bytes, value: bytes):
        """
        Insert or update a node in the tree and update the hashes/commitments
        """

        root = self.root

        path = self.find_path_to_node(root, key)
        last_node = path[-1][0]

        # Insert
        if last_node is None:
            path.pop()
            self._insert(path[-1][0], key, value, update=False)
            new_node = self.find_node(path[-1][0], key)
            new_node.node_hash()
            path.append((new_node, None))
            value_change = int_from_bytes(new_node.hash) % self.modulus

        # Update
        elif last_node.key == key:
            old_hash = last_node.hash
            last_node.value = value
            last_node.node_hash()
            new_hash = last_node.hash
            value_change = (int_from_bytes(
                new_hash) - int_from_bytes(old_hash) + self.modulus) % self.modulus

        for node, edge in reversed(path):
            if edge is None:
                continue

            old_hash = node.hash
            if node.commitment is None:
                self.add_node_hash(node)
            else:
                node.commitment.add(
                    self.setup["g1_lagrange"][edge].dup().mult(value_change))
                node.node_hash()
            new_hash = node.hash
            value_change = (int_from_bytes(
                new_hash) - int_from_bytes(old_hash) + self.modulus) % self.modulus

    def delete_vc_node(self, key: bytes):
        """
        Delete a node in the tree and update the hashes/commitments
        """
        root = self.root

        node = self.find_node(root, key)
        if node is None:
            return

        children = sum(1 for child in [
                       node.left, node.right] if child is not None)

        # Leaf node
        if children == 0:
            path = self.find_path_to_node(root, key)
            node_to_delete = path[-1][0]
            path.pop()
            node_to_update = path[-1][0]
            if path[-1][1] == 0:
                node_to_update.left = None
            elif path[-1][1] == 1:
                node_to_update.right = None
            value_change = (- int_from_bytes(node_to_delete.hash) +
                            self.modulus) % self.modulus
            del node_to_delete

        # Parent with only child
        elif children == 1:
            path = self.find_path_to_node(root, key)
            node_to_delete = path[-1][0]
            node_to_pullup = next(child for child in [
                                  node_to_delete.left, node_to_delete.right] if child is not None)
            

            path.pop()
            node_to_update, node_edge = path[-1]
            if node_edge == 0:
                node_to_update.left = node_to_pullup
            elif node_edge == 1:
                node_to_update.right = node_to_pullup
            value_change = (int_from_bytes(node_to_pullup.hash) -
                            int_from_bytes(node_to_delete.hash) + self.modulus) % self.modulus
            del node_to_delete

        # Parent with two children
        elif children == 2:
            inorder_succ = self.find_min(node.right)
            path = self.find_path_to_node(root, inorder_succ.key)
            node.key = inorder_succ.key
            node.value = inorder_succ.value
            node_to_delete = inorder_succ
            path.pop()
            node_to_update = path[-1][0]
            if path[-1][1] == 0:  # Same as node != node_to_update
                node_to_update.left = node_to_delete.right
            elif path[-1][1] == 1:  # Same as node == node_to_update
                node_to_update.right = node_to_delete.right

            if node_to_delete.is_leaf():
                value_change = (- int_from_bytes(node_to_delete.hash) +
                                self.modulus) % self.modulus
            else:
                value_change = (int_from_bytes(node_to_delete.right.hash) - int_from_bytes(node_to_delete.hash)
                                + self.modulus) % self.modulus
            del node_to_delete

        for node, edge in reversed(path):
            old_hash = node.hash
            if node.commitment is None:
                self.add_node_hash(node)
            else:
                node.commitment.add(
                    self.setup["g1_lagrange"][edge].dup().mult(value_change))
                node.node_hash()
            new_hash = node.hash
            value_change = (int_from_bytes(
                new_hash) - int_from_bytes(old_hash) + self.modulus) % self.modulus

    def find_min(self, node: VBSTNode) -> VBSTNode:
        """
        Find the minimum node from a given node
        """
        while node.left is not None:
            node = node.left
        return node

    def find_node(self, node: VBSTNode, key: bytes) -> VBSTNode:
        """
        Search for a node in the tree with key
        """
        while node is not None:
            if key == node.key:
                return node
            elif key < node.key:
                node = node.left
            elif key > node.key:
                node = node.right
        return None

    def find_path_to_node(self, node: VBSTNode, key: bytes) -> list:
        """
        Returns the path from node to a the node with key,
        returns None at the end of path if node is not found
        """
        path = []
        while node is not None:
            if key == node.key:
                path.append((node, None))
                break
            elif key < node.key:
                edge = 0  # edge 0 for left
            elif key > node.key:
                edge = 1  # edge 1 for right
            path.append((node, edge))
            node = node.left if edge == 0 else node.right

        if node is None:
            path.append((None, None))

        return path

    def add_node_hash(self, node: VBSTNode):
        """
        Adds node hashes and commitments recursively down the tree
        """
        if node.is_leaf():
            node.node_hash()
        else:
            values = {}
            nodes = [node.left, node.right]
            for i in range(len(nodes)):
                if nodes[i] is None:
                    continue

                if nodes[i].hash is None:
                    self.add_node_hash(nodes[i])
                values[i] = int_from_bytes(nodes[i].hash)
            commitment = self.kzg.compute_commitment_lagrange(values)
            node.commitment = commitment
            node.node_hash()

    def check_valid_tree(self, node: VBSTNode):
        """
        Check if the hashes and commitments are valid down the tree
        """

        if node.is_leaf():
            assert node.hash == hash([node.key, node.value])
        else:
            values = {}
            nodes = [node.left, node.right]
            for i in range(len(nodes)):
                if nodes[i] is None:
                    continue

                if nodes[i].hash is None:
                    self.add_node_hash(nodes[i])
                values[i] = int_from_bytes(nodes[i].hash)
                self.check_valid_tree(nodes[i])
            commitment = self.kzg.compute_commitment_lagrange(values)

            assert node.commitment.is_equal(commitment)
            assert node.hash == hash(
                [node.commitment.compress(), node.key, node.value])

    def tree_structure(self, node, level: int = 0, prefix: str = "Root", structure: list = None):
        """
        Returns the tree structure as a list of dictionaries
        """

        if structure is None:
            structure = []

        if node is not None:
            self.tree_structure(node.left, level + 1, "L", structure)
            info = {"position": " " * level * 2 + prefix + str(level),
                    "key": int_from_bytes(node.key),
                    "value": int_from_bytes(node.value)}
            structure.append(info)
            self.tree_structure(node.right, level + 1, "R", structure)

        return structure

    def inorder_traversal(self, node: VBSTNode, order: list = None) -> list:
        """
        Inorder traversal of the tree
        """
        if order is None:
            order = []

        if node is not None:
            self.inorder_traversal(node.left, order)
            order.append(int_from_bytes(node.key))
            self.inorder_traversal(node.right, order)

        return order


if __name__ == "__main__":
    # Parameters
    MODULUS = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    WIDTH_BITS = 1
    WIDTH = 2**WIDTH_BITS
    PRIMITIVE_ROOT = 7
    SECRET = 8927347823478352432985

    # Number of keys to insert, delete, and add
    NUMBER_INITIAL_KEYS = 2**13
    NUMBER_ADDED_KEYS = 2**7
    NUMBER_SEARCH_KEYS = 0
    NUMBER_DELETED_KEYS = 2**7
    KEY_RANGE = 2**256-1

    if len(sys.argv) > 1:
        WIDTH_BITS = int(sys.argv[1])
        WIDTH = 2 ** WIDTH_BITS

        KEY_RANGE = 2 ** int(sys.argv[2])
        NUMBER_INITIAL_KEYS = 2 ** int(sys.argv[3])
        NUMBER_ADDED_KEYS = 2 ** int(sys.argv[4]) if int(sys.argv[4]) != 0 else 0
        NUMBER_SEARCH_KEYS = 2 ** int(sys.argv[5]) if int(sys.argv[5]) != 0 else 0
        NUMBER_DELETED_KEYS = 2 ** int(sys.argv[6]) if int(sys.argv[6]) != 0 else 0

    # Generate setup
    kzg_integration = KzgIntegration(SECRET, MODULUS, WIDTH, PRIMITIVE_ROOT)

    # Generate tree
    root_val, root_value = randint(0, KEY_RANGE), randint(0, KEY_RANGE)
    root = VBSTNode(int_to_bytes(root_val), int_to_bytes(root_value))
    vbst = VBST(kzg_integration, root)

    # Insert nodes
    values = {}

    time_a = time()
    for i in range(NUMBER_INITIAL_KEYS):
        key, value = randint(0, KEY_RANGE), randint(0, KEY_RANGE)
        vbst.insert_node(int_to_bytes(key), int_to_bytes(value))
        values[key] = value
    time_b = time()

    time_initial = time_b - time_a
    print("Inserted {0} elements in {1:.3f} s".format(NUMBER_INITIAL_KEYS, time_initial), file=sys.stderr)

    time_a = time()
    vbst.add_node_hash(vbst.root)
    time_b = time()
    compute_root = time_b - time_a

    print("Computed VBST root in {0:.3f} s".format(compute_root), file=sys.stderr)
    
    # time_a = time()
    # vbst.check_valid_tree(vbst.root)
    # time_b = time()
    # compute_tree_valid = time_b - time_a

    # print("[Checked tree valid: {0:.3f} s]".format(compute_tree_valid), file=sys.stderr)

    time_to_add = None
    check_valid_tree_after_add = None
    if NUMBER_ADDED_KEYS > 0:

        time_x = time()
        for i in range(NUMBER_ADDED_KEYS):
            key, value = randint(0, KEY_RANGE), randint(0, KEY_RANGE)
            vbst.upsert_vc_node(int_to_bytes(key), int_to_bytes(value))
            values[key] = value
        time_y = time()

        time_to_add = time_y - time_x
        print("Additionally inserted {0} elements in {1:.3f} s".format(NUMBER_ADDED_KEYS, time_to_add), file=sys.stderr)

        time_a = time()
        vbst.check_valid_tree(root)
        time_b = time()
        check_valid_tree_after_add = time_b - time_a

        print("[Checked tree valid: {0:.3f} s]".format(check_valid_tree_after_add), file=sys.stderr)


    time_to_search = None
    if NUMBER_SEARCH_KEYS > 0:
        all_keys = list(values.keys())
        shuffle(all_keys)

        keys_to_search = all_keys[:NUMBER_SEARCH_KEYS]

        time_a = time()
        for key in keys_to_search:
            assert vbst.find_node(vbst.root, int_to_bytes(key)) is not None
        time_b = time()

        time_to_search = time_b - time_a
        print("Searched for {0} elements in {1:.3f} s".format(NUMBER_SEARCH_KEYS, time_to_search), file=sys.stderr)


    time_to_delete = None
    check_valid_tree_after_delete = None
    if NUMBER_DELETED_KEYS > 0:
        all_keys = list(values.keys())
        shuffle(all_keys)

        keys_to_delete = all_keys[:NUMBER_DELETED_KEYS]

        time_a = time()
        for key in keys_to_delete:
            vbst.delete_vc_node(int_to_bytes(key))
            del values[key]
        time_b = time()

        time_to_delete = time_b - time_a
        print("Deleted {0} elements in {1:.3f} s".format(NUMBER_DELETED_KEYS, time_to_delete), file=sys.stderr)

        time_a = time()
        vbst.check_valid_tree(vbst.root)
        check_valid_tree_after_delete = time_b - time_a
        
        print("[Checked tree valid: {0:.3f} s]".format(check_valid_tree_after_delete), file=sys.stderr)

    if len(sys.argv) > 1:
        print("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}\t{8}\t{9}\t{10}\t{11}\t{12}\t{13}\t{14}".format(
            'VBST', WIDTH_BITS, WIDTH, KEY_RANGE, NUMBER_INITIAL_KEYS, NUMBER_ADDED_KEYS, 
            time_initial, compute_root, 
            time_to_add if time_to_add is not None else '',
            check_valid_tree_after_add if check_valid_tree_after_add is not None else '',
            NUMBER_SEARCH_KEYS if NUMBER_SEARCH_KEYS != 0 else '',
            time_to_search if time_to_search is not None else '',
            NUMBER_DELETED_KEYS if NUMBER_DELETED_KEYS != 0 else '', 
            time_to_delete if time_to_delete is not None else '', 
            check_valid_tree_after_delete if check_valid_tree_after_delete is not None else ''
        ))