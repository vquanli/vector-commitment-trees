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
        if isinstance(a, tuple):
            b += hash(a)
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


class VBTreeNode:
    def __init__(self, keys: list = None, values: list = None):
        self.keys = keys if keys is not None else []
        self.values = values if values is not None else []
        self.children = []
        self.hash = None
        self.commitment = blst.G1().mult(0)

    def node_hash(self):
        if self.is_leaf():
            self.hash = hash(self.keys + self.values)
        else:
            self.hash = hash([self.commitment.compress()] +
                             self.keys + self.values)

    def key_count(self):
        return len(self.keys)

    def child_count(self):
        return len(self.children)

    def is_leaf(self) -> bool:
        return self.children == []

    def show_keys(self):
        return [(int_from_bytes(key), int_from_bytes(value)) for key, value in zip(self.keys, self.values)]


class VBTree:
    def __init__(self, kzg: KzgIntegration, root: VBTreeNode):
        self.kzg = kzg.kzg_utils()
        self.setup = kzg.setup
        self.root = root
        assert kzg.width // 2 >= 2
        self.min_degree = kzg.width // 2
        self.modulus = kzg.modulus
        self.width = kzg.width

    def _insert(self, node: VBTreeNode, key: bytes, value: bytes, update: bool):
        """
        Insert command for the tree
        """
        t = self.min_degree
        key_count = node.key_count()

        if key_count == (2 * t) - 1:
            raise Exception("Error, Node is full")

        idx = key_count - 1
        if node.is_leaf():
            while idx >= 0 and key < node.keys[idx]:
                idx -= 1
            node.keys.insert(idx + 1, key)
            node.values.insert(idx + 1, value)
        else:
            while idx >= 0 and key < node.keys[idx]:
                idx -= 1

            idx += 1
            if node.children[idx].key_count() == (2 * t) - 1:
                self._split_child(node, idx)
                if key > node.keys[idx]:
                    idx += 1
            self._insert(node.children[idx], key, value, update)

        return node

    def _split_child(self, node: VBTreeNode, idx: int):
        """
        Split a child node
        """

        t = self.min_degree

        child = node.children[idx]
        new_node = VBTreeNode()
        node.children.insert(idx + 1, new_node)

        node.keys.insert(idx, child.keys[t - 1])
        node.values.insert(idx, child.values[t - 1])

        new_node.keys = child.keys[t: (2 * t) - 1]
        new_node.values = child.values[t: (2 * t) - 1]
        child.keys = child.keys[0:t - 1]
        child.values = child.values[0:t - 1]

        if not child.is_leaf():
            new_node.children = child.children[t: (2 * t)]
            child.children = child.children[0: t]

    def insert_node(self, key: bytes, value: bytes, update: bool = False):
        """
        Insert a node into the tree
        """
        find_node = self.find_node(self.root, key)
        if find_node is not None:
            node, idx = find_node
            if update:
                node.values[idx] = value
            return

        t = self.min_degree
        root = self.root
        if root.key_count() == (2 * t) - 1:
            new_node = VBTreeNode()
            self.root = new_node
            new_node.children.insert(0, root)
            self._split_child(new_node, 0)
            self._insert(new_node, key, value, update)
        else:
            self._insert(root, key, value, update)

    def upsert_vc_node(self, key: bytes, value: bytes):
        """
        Insert or update a node in the tree and update the hashes/commitments
        """
        t = self.min_degree
        root = self.root

        path = self.find_path_to_node(root, key)
        last_node, last_idx = path[-1]

        # Update
        if last_idx < last_node.key_count() and last_node.keys[last_idx] == key:
            old_hash = last_node.hash
            last_node.values[last_idx] = value
            last_node.node_hash()
            new_hash = last_node.hash
            value_change = (int_from_bytes(
                new_hash) - int_from_bytes(old_hash) + self.modulus) % self.modulus

        # Insert
        else:
            splits = [True if path[i][0].key_count() == (
                2 * t) - 1 else False for i in range(len(path))]
            split_counts = splits.count(True)

            if split_counts == 0:
                old_hash = last_node.hash
                self.insert_node(key, value)
                last_node.node_hash()
                new_hash = last_node.hash
                value_change = (int_from_bytes(
                    new_hash) - int_from_bytes(old_hash) + self.modulus) % self.modulus

            else:
                self._insert_vc_node_splits(key, value, path, splits)
                return

        for node, idx in reversed(path):
            if node == last_node:
                continue
            old_hash = node.hash
            if node.commitment is None:
                self.add_node_hash(node)
            else:
                node.commitment.add(
                    self.setup["g1_lagrange"][idx].dup().mult(value_change))
                node.node_hash()
            new_hash = node.hash
            value_change = (int_from_bytes(
                new_hash) - int_from_bytes(old_hash) + self.modulus) % self.modulus

    def _insert_vc_node_splits(self, key: bytes, value: bytes, path: list, splits: list):

        t = self.min_degree

        update_path = []
        for i in range(len(path)):
            node, idx = path[i]
            node_type = 'leaf' if node.is_leaf() else 'inner'
            previous_node = path[i - 1][0]
            previous_idx = path[i - 1][1]
            hash = node.hash
            value_dict = {'node_type': node_type, 'hash': hash}
            if splits[i]:
                if i == 0:
                    value_dict['updated_idx'] = 1 if idx > t - 1 else 0
                    value_dict['split_idx'] = 0 if idx > t - 1 else 1
                else:
                    value_dict['updated_idx'] = previous_idx + \
                        1 if idx > t - 1 else previous_idx
                    value_dict['split_idx'] = previous_idx if idx > t - \
                        1 else previous_idx + 1
                    if not splits[i - 1] and previous_node.child_count() > previous_idx + 1:
                        value_dict['shifted_idx'] = [
                            i + 1 for i in range(previous_idx + 1, previous_node.child_count())]
                    elif splits[i - 1] and t - 1 > previous_idx:
                        value_dict['shifted_idx'] = [
                            i + 1 for i in range(previous_idx + 1, t)]

                if node_type == 'inner':
                    child_hashes = [
                        node.hash for node in node.children[t: (2 * t)]]
                    value_dict['child_hashes'] = child_hashes
                    path[i] = (node, idx % t)
            else:
                if i == 0:
                    continue
                else:
                    value_dict['updated_idx'] = previous_idx
            update_path.append(value_dict)

        self.insert_node(key, value)
        current_node = self.root
        for node in update_path:
            node['updated_node'] = current_node.children[node['updated_idx']]
            if node.get('split_idx') is not None:
                node['split_node'] = current_node.children[node['split_idx']]
            if node.get('shifted_idx') is not None:
                node['shifted_nodes'] = [current_node.children[i]
                                         for i in node['shifted_idx']]
            current_node = node['updated_node']

        update_node_changes = []
        split_node_changes = []

        root_dict = {'node_type': 'root', 'updated_node': self.root}
        update_path.insert(0, root_dict)
        for node in reversed(update_path):

            node['updated_node'].node_hash()

            # Changes to current node
            if node['node_type'] == 'root':
                if update_path[1].get('split_node') is not None:
                    self.add_node_hash(node['updated_node'])
                else:
                    for idx, value_change in update_node_changes:
                        node['updated_node'].commitment.add(
                            self.setup["g1_lagrange"][idx].dup().mult(value_change))
                        node['updated_node'].node_hash()
                return
            if node['node_type'] == 'inner':
                if node.get('split_node') is not None:
                    node['split_node'].node_hash()
                    changes_to_original = [
                        (t + i, (- int_from_bytes(node['child_hashes'][i]) + self.modulus) % self.modulus) for i in range(t)]
                    changes_to_split = [
                        (i, int_from_bytes(node['child_hashes'][i]) % self.modulus) for i in range(t)]
                    if node['updated_idx'] < node['split_idx']:
                        update_node_changes = changes_to_original + update_node_changes
                        split_node_changes = changes_to_split
                    else:
                        update_node_changes = changes_to_split + update_node_changes
                        split_node_changes = changes_to_original

            # Update commits to current nodes
            if len(split_node_changes) > 0:
                for idx, value_change in split_node_changes:
                    node['split_node'].commitment.add(
                        self.setup["g1_lagrange"][idx].dup().mult(value_change))
                    node['split_node'].node_hash()
                split_node_changes = []

            if len(update_node_changes) > 0:
                for idx, value_change in update_node_changes:
                    node['updated_node'].commitment.add(
                        self.setup["g1_lagrange"][idx].dup().mult(value_change))
                    node['updated_node'].node_hash()
                update_node_changes = []

            # Changes to next node
            if node.get('split_node') is not None:
                node['split_node'].node_hash()
                min_idx = min(node['updated_idx'], node['split_idx'])
                nodes = (node['updated_node'], node['split_node']) if node['updated_idx'] < node['split_idx'] else (
                    node['split_node'], node['updated_node'])
                change_to_original = (int_from_bytes(
                    nodes[0].hash) - int_from_bytes(node['hash']) + self.modulus) % self.modulus
                change_to_split = int_from_bytes(nodes[1].hash) % self.modulus

                update_node_changes.append((min_idx, change_to_original))
                update_node_changes.append((min_idx + 1, change_to_split))

                if node.get('shifted_nodes') is not None:
                    for i in range(len(node['shifted_nodes'])):
                        shifted_hash = node['shifted_nodes'][i].hash
                        change_remove_hash = (- int_from_bytes(shifted_hash) +
                                              self.modulus) % self.modulus
                        change_add_hash = int_from_bytes(
                            shifted_hash) % self.modulus
                        update_node_changes.append(
                            (node['shifted_idx'][i] - 1, change_remove_hash))
                        update_node_changes.append(
                            (node['shifted_idx'][i], change_add_hash))
            else:
                update_change = (int_from_bytes(
                    node['updated_node'].hash) - int_from_bytes(node['hash']) + self.modulus) % self.modulus
                update_node_changes.append(
                    (node['updated_idx'], update_change))

    def find_node(self, node: VBTreeNode, key: bytes):
        """
        Search for a node in the tree
        """

        key_count = node.key_count()

        while node is not None:
            i = 0
            while i < key_count and key > node.keys[i]:
                i += 1
            if i < key_count and key == node.keys[i]:
                return (node, i)
            elif node.is_leaf():
                break
            else:
                return self.find_node(node.children[i], key)

        return None

    def find_path_to_node(self, node: VBTreeNode, key: bytes, path: list = None) -> list:
        """
        Returns the path from node to a node with key with the last element being none if the node does not exist
        """

        key_count = node.key_count()

        if path is None:
            path = []

        while node is not None:
            i = 0
            while i < key_count and key > node.keys[i]:
                i += 1
            path.append((node, i))
            if i < key_count and key == node.keys[i]:
                break
            elif node.is_leaf():
                break
            else:
                return self.find_path_to_node(node.children[i], key, path)
        return path

    def add_node_hash(self, node: VBTreeNode):
        """
        Add the hash of a node to the node itself
        """
        if node.is_leaf():
            node.node_hash()
        else:
            values = {}
            nodes = node.children
            for i in range(len(nodes)):

                if nodes[i].hash is None:
                    self.add_node_hash(nodes[i])
                values[i] = int_from_bytes(nodes[i].hash)
            commitment = self.kzg.compute_commitment_lagrange(values)
            node.commitment = commitment
            node.node_hash()

    def check_valid_tree(self, node: VBTreeNode):
        """
        Check if the tree is valid
        """

        if node.is_leaf():
            assert node.hash == hash(node.keys + node.values)
        else:
            values = {}
            nodes = node.children
            for i in range(len(nodes)):

                if nodes[i].hash is None:
                    self.add_node_hash(nodes[i])
                values[i] = int_from_bytes(nodes[i].hash)
                self.check_valid_tree(nodes[i])
            commitment = self.kzg.compute_commitment_lagrange(values)
            assert node.commitment.is_equal(commitment)
            assert node.hash == hash(
                [node.commitment.compress()] + node.keys + node.values)

    def tree_structure(self, node, level: int = 0, prefix: str = "Root", child_idx=None, structure: list = None):
        """
        Print the B-tree structure in order
        """

        if structure is None:
            structure = []

        if node is not None:
            info = {"position": " " * level * 2 + prefix + str(level),
                    "keys": [int_from_bytes(key) for key in node.keys],
                    "values": [int_from_bytes(value) for value in node.values],
                    "child_index": child_idx}
            structure.append(info)
            for i in range(node.child_count()):
                self.tree_structure(
                    node.children[i], level + 1, f"L{i}", i, structure)

        return structure

    def print_path(self, path):
        for node, idx in path:
            print(node, [(int_from_bytes(key), int_from_bytes(value))
                  for key, value in zip(node.keys, node.value)], idx)

if __name__ == "__main__":
    # Parameters
    MODULUS = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    WIDTH = 4
    PRIMITIVE_ROOT = 7
    SECRET = 8927347823478352432985

    # Number of keys to insert, delete, and add
    NUMBER_INITIAL_KEYS = 2**8
    NUMBER_ADDED_KEYS = 2**12
    NUMBER_DELETED_KEYS = 2**12
    KEY_RANGE = 2**4

    # Generate setup
    kzg_integration = KzgIntegration(SECRET, MODULUS, WIDTH, PRIMITIVE_ROOT)

    # Generate tree
    root_val, root_value = randint(0, KEY_RANGE), randint(0, KEY_RANGE)
    root = VBTreeNode([int_to_bytes(root_val)], [int_to_bytes(root_value)])
    v_b_tree = VBTree(kzg_integration, root)

    # Insert nodes

    values = {}
    for i in range(NUMBER_INITIAL_KEYS):
        key, value = randint(0, KEY_RANGE), randint(0, KEY_RANGE)
        v_b_tree.insert_node(int_to_bytes(key), int_to_bytes(value))
        values[key] = value

    print("Inserted {0} elements".format(NUMBER_INITIAL_KEYS), file=sys.stderr)

    time_a = time()
    v_b_tree.add_node_hash(v_b_tree.root)
    time_b = time()

    print(
        "Computed VB-tree root in {0:.3f} s".format(time_b - time_a), file=sys.stderr)

    if NUMBER_ADDED_KEYS > 0:
        time_a = time()
        v_b_tree.check_valid_tree(v_b_tree.root)
        time_b = time()

        print("[Checked tree valid: {0:.3f} s]".format(
            time_b - time_a), file=sys.stderr)

        time_x = time()
        for i in range(NUMBER_ADDED_KEYS):
            key, value = randint(0, KEY_RANGE), randint(0, KEY_RANGE)
            v_b_tree.upsert_vc_node(int_to_bytes(key), int_to_bytes(value))
            values[key] = value
        time_y = time()

        print("Additionally inserted {0} elements in {1:.3f} s".format(
            NUMBER_ADDED_KEYS, time_y - time_x), file=sys.stderr)

        time_a = time()
        v_b_tree.check_valid_tree(v_b_tree.root)
        time_b = time()

        print("[Checked tree valid: {0:.3f} s]".format(
            time_b - time_a), file=sys.stderr)

    # if NUMBER_DELETED_KEYS > 0:
    #     all_keys = list(values.keys())
    #     shuffle(all_keys)

    #     keys_to_delete = all_keys[:NUMBER_DELETED_KEYS]

    #     time_a = time()
    #     for key in keys_to_delete:
    #         v_b_tree.delete_vc_node(int_to_bytes(key))
    #         del values[key]
    #     time_b = time()

    #     print("Deleted {0} elements in {1:.3f} s".format(NUMBER_DELETED_KEYS, time_b - time_a), file=sys.stderr)

    #     time_a = time()
    #     v_b_tree.check_valid_tree(v_b_tree.root)
    #     time_b = time()

    #     print("[Checked tree valid: {0:.3f} s]".format(time_b - time_a), file=sys.stderr)