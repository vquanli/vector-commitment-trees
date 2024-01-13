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
            node_to_update = path[-1][0]
            if path[-1][1] == 0:
                node_to_update.left = node_to_pullup
            elif path[-1][1] == 1:
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
    WIDTH = 2
    PRIMITIVE_ROOT = 7
    SECRET = 8927347823478352432985

    # Number of keys to insert, delete, and add
    NUMBER_INITIAL_KEYS = 2**13
    NUMBER_ADDED_KEYS = 2**7
    NUMBER_DELETED_KEYS = 2**7
    KEY_RANGE = 2**256-1

    # Generate setup
    kzg_integration = KzgIntegration(SECRET, MODULUS, WIDTH, PRIMITIVE_ROOT)

    # Generate tree
    root_val, root_value = randint(0, KEY_RANGE), randint(0, KEY_RANGE)
    root = VBSTNode(int_to_bytes(root_val), int_to_bytes(root_value))
    vbst = VBST(kzg_integration, root)

    # Insert nodes

    values = {}
    for i in range(NUMBER_INITIAL_KEYS):
        key, value = randint(0, KEY_RANGE), randint(0, KEY_RANGE)
        vbst.insert_node(int_to_bytes(key), int_to_bytes(value))
        values[key] = value

    print("Inserted {0} elements".format(NUMBER_INITIAL_KEYS), file=sys.stderr)

    time_a = time()
    vbst.add_node_hash(vbst.root)
    time_b = time()

    print("Computed VBST root in {0:.3f} s".format(
        time_b - time_a), file=sys.stderr)

    if NUMBER_ADDED_KEYS > 0:
        time_a = time()
        vbst.check_valid_tree(vbst.root)
        time_b = time()

        print("[Checked tree valid: {0:.3f} s]".format(
            time_b - time_a), file=sys.stderr)

        time_x = time()
        for i in range(NUMBER_ADDED_KEYS):
            key, value = randint(0, KEY_RANGE), randint(0, KEY_RANGE)
            vbst.upsert_vc_node(int_to_bytes(key), int_to_bytes(value))
            values[key] = value
        time_y = time()

        print("Additionally inserted {0} elements in {1:.3f} s".format(
            NUMBER_ADDED_KEYS, time_y - time_x), file=sys.stderr)

        time_a = time()
        vbst.check_valid_tree(root)
        time_b = time()

        print("[Checked tree valid: {0:.3f} s]".format(
            time_b - time_a), file=sys.stderr)

    if NUMBER_DELETED_KEYS > 0:
        all_keys = list(values.keys())
        shuffle(all_keys)

        keys_to_delete = all_keys[:NUMBER_DELETED_KEYS]

        time_a = time()
        for key in keys_to_delete:
            vbst.delete_vc_node(int_to_bytes(key))
            del values[key]
        time_b = time()

        print("Deleted {0} elements in {1:.3f} s".format(
            NUMBER_DELETED_KEYS, time_b - time_a), file=sys.stderr)

        time_a = time()
        vbst.check_valid_tree(root)
        time_b = time()

        print("[Checked tree valid: {0:.3f} s]".format(
            time_b - time_a), file=sys.stderr)
