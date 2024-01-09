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
    def __init__(self, modulus: int, width: int, primitive_root: int):
        self.modulus = modulus
        self.width = width
        assert pow(primitive_root, (modulus - 1) // width, modulus) != 1
        assert pow(primitive_root, modulus - 1, modulus) == 1
        self.root_of_unity = pow(primitive_root, (modulus - 1) // width, modulus)

    def generate_setup(self, size, secret):
        """
        Generates a setup in the G1 group and G2 group, as well as the Lagrange polynomials in G1 (via FFT)
        """
        g1_setup = [blst.G1().mult(pow(secret, i, self.modulus))
                    for i in range(size)]
        g2_setup = [blst.G2().mult(pow(secret, i, self.modulus))
                    for i in range(size)]
        g1_lagrange = fft(g1_setup, self.modulus, self.root_of_unity, inv=True)
        return {"g1": g1_setup, "g2": g2_setup, "g1_lagrange": g1_lagrange}

    def kzg_utils(self, setup: dict):
        primefield = PrimeField(self.modulus, self.width)
        domain = [pow(self.root_of_unity, i, self.modulus) for i in range(self.width)]
        return KzgUtils(self.modulus, self.width, domain, setup, primefield)
  

class VBPlusTreeNode:
    def __init__(self, node_type: str = 'leaf', keys: list = None, values: list = None):
        self.node_type = node_type
        self.parent = None
        self.hash = None
        self.commitment = blst.G1().mult(0)

        assert self.node_type in ['leaf', 'inner']

        if node_type == 'leaf':
            self.keys = keys if keys is not None else []
            self.values = values if values is not None else []
            self.next_leaf = None
        if node_type == 'inner':
            self.keys = []
            self.children = []

    def node_hash(self):
        if self.node_type == 'leaf':
            self.hash = hash(self.keys + self.values)
        elif self.node_type == 'inner':
            self.hash = hash([self.commitment.compress()] + self.keys)

    def key_count(self):
        return len(self.keys)

    def child_count(self):
        if self.node_type == 'inner':
            return len(self.children)
        return None

    def is_leaf(self) -> bool:
        if self.node_type == 'leaf':
            return True
        return False

    def show_key_values(self):
        if self.node_type == 'leaf':
            return [(int_from_bytes(key), int_from_bytes(value)) for key, value in zip(self.keys, self.values)]
        elif self.node_type == 'inner':
            return [int_from_bytes(key) for key in self.keys]

class VBPlusTree:
    def __init__(self, setup: dict, kzg: KzgUtils, root: VBPlusTreeNode, min_degree: int, modulus: int, width: int):
        self.setup = setup
        self.kzg = kzg
        self.root = root
        self.min_degree = min_degree if min_degree > 2 else 2
        self.modulus = modulus
        self.width = width

    def _insert(self, path: list, key: bytes, value: bytes):
        """
        Insert command for the tree
        """

        t = self.min_degree
        node, idx = path.pop()
        node_type = node.node_type

        parent_path = None if len(path) == 0 else path[-1]

        if node_type == 'leaf':
            node.keys.insert(idx, key)
            node.values.insert(idx, value)
            if parent_path is not None and idx == 0:
                p_node, p_idx = parent_path
                if p_idx != 0:
                    p_node.keys[p_idx - 1] = node.keys[0]

        if node.key_count() > (2 * t) - 1:
            if parent_path is None:
                new_node = VBPlusTreeNode(node_type='inner')
                self.root = new_node
                new_node.children.insert(0, node)
                parent_path = (new_node, 0)
            p_node, p_idx = parent_path
            self._split_node(node, node_type, p_node, p_idx)
        else:
            return
        
        if len(path) > 0:
            self._insert(path, key, value)
            

    def _split_node(self, node: VBPlusTreeNode, node_type: str, parent_node: VBPlusTreeNode, split_idx: int):
        """
        Split a child node
        """
        t = self.min_degree

        new_node = VBPlusTreeNode(node_type=node_type)

        if node_type == 'leaf':
            new_node.keys = node.keys[t:]
            new_node.values = node.values[t:]
            node.keys = node.keys[:t]
            node.values = node.values[:t]
            node.next_leaf = new_node
            parent_node.children.insert(split_idx + 1, new_node)
            parent_node.keys.insert(split_idx, new_node.keys[0])

        else:
            new_node.keys = node.keys[t+1:]
            new_node.children = node.children[t+1:]
            parent_node.keys.insert(split_idx, node.keys[t])
            node.keys = node.keys[:t]
            node.children = node.children[:t+1]
            parent_node.children.insert(split_idx + 1, new_node)
        

    def insert_node(self, key: bytes, value: bytes, update: bool = False):
        """
        Insert a node into the tree
        """
        root = self.root
        path_to_leaf = self.find_path_to_leaf(root, key)
        leaf_node, leaf_idx = path_to_leaf[-1]

        # Update node
        if leaf_idx < leaf_node.key_count() and leaf_node.keys[leaf_idx] == key:
            if update:
                leaf_node.values[leaf_idx] = value
        # Insert node
        else:
            self._insert(path_to_leaf, key, value)

    def upsert_vc_node(self, key: bytes, value: bytes):
        """
        Insert a node into the tree
        """
        t = self.min_degree
        root = self.root
        path = self.find_path_to_leaf(root, key)
        leaf_node, leaf_idx = path[-1]

        # Update
        if leaf_idx < leaf_node.key_count() and leaf_node.keys[leaf_idx] == key:
            old_hash = leaf_node.hash
            leaf_node.values[leaf_idx] = value
            leaf_node.node_hash()
            new_hash = leaf_node.hash
            value_change = (int_from_bytes(new_hash) - int_from_bytes(old_hash) + self.modulus) % self.modulus

        # Insert
        else:
            if leaf_node.key_count() < (2 * t) - 1:
                old_hash = leaf_node.hash
                self._insert(path, key, value)
                leaf_node.node_hash()
                new_hash = leaf_node.hash
                value_change = (int_from_bytes(new_hash) - int_from_bytes(old_hash) + self.modulus) % self.modulus
            else:
                self._insert_vc_node_splits(key, value, path)
                return

        for node, idx in reversed(path):
            if node.node_type == 'leaf':
                continue
            old_hash = node.hash
            if node.commitment is None:
                self.add_node_hash(node)
            else:
                node.commitment.add(self.setup["g1_lagrange"][idx].dup().mult(value_change))
                node.node_hash()
            new_hash = node.hash
            value_change = (int_from_bytes(new_hash) - int_from_bytes(old_hash) + self.modulus) % self.modulus

    def _insert_vc_node_splits(self, key: bytes, value: bytes, path: list):
        
        t = self.min_degree
        idx_for_split = next((i for i, (node, _) in enumerate(reversed(path)) if node.key_count() != (2 * t) - 1), len(path))
        idx_for_split = len(path) - idx_for_split


        update_path = []
        for i in range(len(path)):
            node, idx = path[i]
            node_type = node.node_type
            previous_node = path[i - 1][0]
            previous_idx = path[i - 1][1]
            hash = node.hash
            value_dict = {'node_type': node_type, 'updated_idx': idx, 'hash': hash}
            if i >= idx_for_split:
                if i == 0:
                    value_dict['updated_idx'] = 1 if idx > t - 1 else 0
                    value_dict['split_idx'] = 0 if idx > t - 1 else 1
                    if idx == t:
                        value_dict['branch_idx'] = value_dict['split_idx']
                        del value_dict['split_idx']

                else:
                    value_dict['updated_idx'] = previous_idx + 1 if idx > t - 1 else previous_idx
                    value_dict['split_idx'] = previous_idx if idx > t - 1 else previous_idx + 1
                    if i == idx_for_split and previous_node.child_count() > previous_idx + 1:
                        value_dict['shifted_idx'] = [i + 1 for i in range(previous_idx + 1, previous_node.child_count())]

                    elif i - 1 >= idx_for_split:
                        value_dict['updated_idx'] = value_dict['updated_idx'] % (t + 1)
                        value_dict['split_idx'] = value_dict['split_idx'] % (t + 1)
                        if t - 1 > previous_idx % t:
                            value_dict['shifted_idx'] = [i + 1 for i in range(previous_idx % t + 1, t)]
                            if previous_idx > t - 1:
                                value_dict['shifted_idx'] = [i - 1 for i in value_dict['shifted_idx']]
                
                    if idx == t or previous_idx == t:
                        if node_type == 'leaf' and idx == t and previous_idx != t:
                            pass
                        else:
                            value_dict['branch_idx'] = value_dict['split_idx']
                            del value_dict['split_idx']
                            if idx != t:
                                value_dict['branch_stop'] = True
                                if idx < t and value_dict.get('shifted_idx') is not None:
                                    value_dict['branch_shifted_idx'] = value_dict['shifted_idx']
                                    del value_dict['shifted_idx']


                if node_type == 'inner':
                    if idx > t - 1:
                        child_hashes = [node.hash for node in node.children[t + 1:]]
                    else:
                        child_hashes = [node.hash for node in node.children[t:]]
                    value_dict['child_hashes'] = child_hashes
                    if value_dict.get('branch_idx') is not None and value_dict.get('branch_stop') is None:
                        end_of_branch = i
                        while path[end_of_branch][1] == t and end_of_branch < len(path) - 1:
                            end_of_branch += 1
                        if path[end_of_branch][1] < t:
                            branch_idx = value_dict['branch_idx']
                            value_dict['branch_idx'] = value_dict['updated_idx']
                            value_dict['updated_idx'] = branch_idx
                            if value_dict.get('shifted_idx') is not None:
                                value_dict['branch_shifted_idx'] = value_dict['shifted_idx']
                                del value_dict['shifted_idx']

            else:
                if i == 0:
                    continue
                value_dict['updated_idx'] = previous_idx
            update_path.append(value_dict)
        
        self._insert(path, key, value)

        current_node = self.root
        branch_node = None
        for node in update_path:
            node['updated_node'] = current_node.children[node['updated_idx']]
            if node.get('split_idx') is not None:
                branch_node = None
                node['split_node'] = current_node.children[node['split_idx']]
            if node.get('shifted_idx') is not None:
                node['shifted_nodes'] = [current_node.children[i] for i in node['shifted_idx']]
            if node.get('branch_idx') is not None:
                if branch_node is None:
                    node['branch_node'] = current_node.children[node['branch_idx']]
                else: 
                    node['branch_node'] = branch_node.children[node['branch_idx']]
            if node.get('branch_shifted_idx') is not None:
                if branch_node is None:
                    node['branch_shifted_nodes'] = [current_node.children[i] for i in node['branch_shifted_idx']]
                else:
                    node['branch_shifted_nodes'] = [branch_node.children[i] for i in node['branch_shifted_idx']]
            branch_node = node.get('branch_node')
            if node.get('branch_stop') is not None:
                branch_node = None
            current_node = node['updated_node']

        update_node_changes = []
        split_node_changes = []
        branch_node_changes = []

        root_dict = {'node_type': 'root', 'updated_node': self.root}
        update_path.insert(0, root_dict)
        for node in reversed(update_path):
            
            node['updated_node'].node_hash()

            if node.get('branch_stop') and len(branch_node_changes) > 0:
                update_node_changes.extend(branch_node_changes)
                branch_node_changes = []

            # Changes to current node
            if node['node_type'] == 'root':
                if update_path[1].get('split_idx') is not None or update_path[1].get('branch_idx') is not None:
                    self.add_node_hash(node['updated_node'])
                else:
                    for idx, value_change in update_node_changes:
                        node['updated_node'].commitment.add(self.setup["g1_lagrange"][idx].dup().mult(value_change))
                        node['updated_node'].node_hash()
                return
            if node['node_type'] == 'inner':
                if node.get('split_node') is not None:
                    node['split_node'].node_hash()
                    hashes = node['child_hashes']
                    changes_to_original = [(2 * t - len(hashes) + i, (- int_from_bytes(hashes[i]) + self.modulus) % self.modulus) for i in range(len(hashes))]
                    changes_to_split = [(i, int_from_bytes(node['child_hashes'][i]) % self.modulus) for i in range(len(hashes))]
                    if node['updated_idx'] < node['split_idx']:
                        update_node_changes = changes_to_original + update_node_changes
                        split_node_changes = changes_to_split
                    else:
                        update_node_changes = changes_to_split + update_node_changes
                        split_node_changes = changes_to_original
                if node.get('branch_node') is not None:
                    node['branch_node'].node_hash()
                    hashes = node['child_hashes']
                    changes_to_original = [(2 * t - len(hashes) + i, (- int_from_bytes(hashes[i]) + self.modulus) % self.modulus) for i in range(len(hashes))]
                    changes_to_branch = [(i, int_from_bytes(hashes[i]) % self.modulus) for i in range(len(hashes))]
                    if abs(node['updated_idx'] - node['branch_idx']) != 1:
                        updated_node_is_original = True if node['updated_idx'] == t else False
                    else:
                        updated_node_is_original = True if node['updated_idx'] < node['branch_idx'] else False

                    if updated_node_is_original:
                        update_node_changes = changes_to_original + update_node_changes
                        branch_node_changes = changes_to_branch + branch_node_changes
                    else:
                        update_node_changes = changes_to_branch + update_node_changes
                        branch_node_changes = changes_to_original + branch_node_changes


            if len(branch_node_changes) > 0:
                for idx, value_change in branch_node_changes:
                    if node.get('branch_node') is not None:
                        node['branch_node'].commitment.add(self.setup["g1_lagrange"][idx].dup().mult(value_change))
                        node['branch_node'].node_hash()
                    else:
                        node['updated_node'].commitment.add(self.setup["g1_lagrange"][idx].dup().mult(value_change))
                        node['updated_node'].node_hash()
                branch_node_changes = []

            # Update commits to current nodes
            if len(split_node_changes) > 0:
                for idx, value_change in split_node_changes:
                    
                    node['split_node'].commitment.add(self.setup["g1_lagrange"][idx].dup().mult(value_change))
                    node['split_node'].node_hash()
                split_node_changes = []


            if len(update_node_changes) > 0:
                for idx, value_change in update_node_changes:
                    node['updated_node'].commitment.add(self.setup["g1_lagrange"][idx].dup().mult(value_change))
                    node['updated_node'].node_hash()
                update_node_changes = []

            # Changes to next node
            if node.get('split_node') is not None or node.get('branch_node') is not None:
                if node.get('split_node') is not None:
                    node['split_node'].node_hash()
                    min_idx = min(node['updated_idx'], node['split_idx'])
                    nodes = (node['updated_node'], node['split_node']) if node['updated_idx'] < node['split_idx'] else (node['split_node'], node['updated_node'])
                    change_to_original = (int_from_bytes(nodes[0].hash) - int_from_bytes(node['hash']) + self.modulus) % self.modulus
                    change_to_split = int_from_bytes(nodes[1].hash) % self.modulus

                    update_node_changes.append((min_idx, change_to_original))
                    update_node_changes.append((min_idx + 1, change_to_split))

                if node.get('branch_node') is not None:
                    node['branch_node'].node_hash()
                    if abs(node['updated_idx'] - node['branch_idx']) != 1:
                        nodes = (node['updated_node'], node['branch_node']) if node['updated_idx'] == t else (node['branch_node'], node['updated_node'])
                    else:
                        nodes = (node['updated_node'], node['branch_node']) if node['updated_idx'] < node['branch_idx'] else (node['branch_node'], node['updated_node'])
                    change_to_original = (int_from_bytes(nodes[0].hash) - int_from_bytes(node['hash']) + self.modulus) % self.modulus
                    change_to_branch = int_from_bytes(nodes[1].hash) % self.modulus
                    if node['updated_node'] == nodes[0]:
                        update_node_changes.append((node['updated_idx'], change_to_original))
                        branch_node_changes.append((node['branch_idx'], change_to_branch))
                    else:
                        update_node_changes.append((node['updated_idx'], change_to_branch))
                        branch_node_changes.append((node['branch_idx'], change_to_original))
            
                if node.get('shifted_nodes') is not None:
                    for i in range(len(node['shifted_nodes'])):
                        shifted_hash = node['shifted_nodes'][i].hash 
                        change_remove_hash = (- int_from_bytes(shifted_hash) + self.modulus) % self.modulus
                        change_add_hash = int_from_bytes(shifted_hash) % self.modulus
                        update_node_changes.append((node['shifted_idx'][i] - 1, change_remove_hash))
                        update_node_changes.append((node['shifted_idx'][i], change_add_hash))

                if node.get('branch_shifted_nodes') is not None:
                    for i in range(len(node['branch_shifted_nodes'])):
                        shifted_hash = node['branch_shifted_nodes'][i].hash 
                        change_remove_hash = (- int_from_bytes(shifted_hash) + self.modulus) % self.modulus
                        change_add_hash = int_from_bytes(shifted_hash) % self.modulus
                        branch_node_changes.append((node['branch_shifted_idx'][i] - 1, change_remove_hash))
                        branch_node_changes.append((node['branch_shifted_idx'][i], change_add_hash))

            else:
                update_change = (int_from_bytes(node['updated_node'].hash) - int_from_bytes(node['hash']) + self.modulus) % self.modulus
                update_node_changes.append((node['updated_idx'], update_change))


    def find_node(self, node: VBPlusTreeNode, key: bytes):
        """
        Search for a node in the tree
        """

        key_count = node.key_count()

        while node is not None:
            i = 0
            while i < key_count and key >= node.keys[i]:
                i += 1
            if node.node_type == 'leaf':
                if i <= key_count and key == node.keys[i - 1]:
                    return (node, i - 1)
                return None

            return self.find_node(node.children[i], key)
        
        return None

    def find_path_to_leaf(self, node: VBPlusTreeNode, key: bytes, path: list = None) -> list:
        """
        Returns the path from node to a node with key with the last element being none if the node does not exist
        """

        key_count = node.key_count()

        if path is None:
            path = []
        
        while node is not None:
            i = 0
            while i < key_count and key >= node.keys[i]:
                i += 1
            if node.node_type == 'leaf':
                if i <= key_count and key == node.keys[i - 1]:
                    i -= 1
                path.append((node, i))
                break

            path.append((node, i))
            return self.find_path_to_leaf(node.children[i], key, path)
                
        return path

    def print_path(self, path):
        for node, idx in path:
            print(node, [(int_from_bytes(key), int_from_bytes(value)) for key, value in zip(node.keys, node.value)], idx)
                

    def add_node_hash(self, node: VBPlusTreeNode):
        """
        Add the hash of a node to the node itself
        """
        if node.node_type == 'leaf':
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

    
    def check_valid_tree(self, node: VBPlusTreeNode):
        """
        Check if the tree is valid
        """
            
        if node.node_type == 'leaf':
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
            assert node.hash == hash([node.commitment.compress()] + node.keys)


    def inorder_tree_structure(self, node, level: int = 0, prefix: str = "Root", child_idx = None, structure: list = None):
        """
        Print the B-tree structure in order
        """

        if structure is None:
            structure = []

        if node is not None:
            info = {"position": " " * level * 2 + prefix + str(level),
                    "keys": [int_from_bytes(key) for key in node.keys],
                    "child_index": child_idx}
            structure.append(info)
            if node.node_type != 'leaf':
                for i in range(node.child_count()):
                    self.inorder_tree_structure(node.children[i], level + 1, f"L{i}", i, structure)

        return structure
    

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
    KEY_RANGE = 2**32

    # Generate setup
    kzg_integration = KzgIntegration(MODULUS, WIDTH, PRIMITIVE_ROOT)
    kzg_setup = kzg_integration.generate_setup(WIDTH, SECRET)
    kzg_utils = kzg_integration.kzg_utils(kzg_setup)

    # Generate tree
    min_degree = WIDTH // 2
    root_val, root_value = randint(0, KEY_RANGE), randint(0, KEY_RANGE)
    root = VBPlusTreeNode('leaf', [int_to_bytes(root_val)], [int_to_bytes(root_value)])
    v_bplus_tree = VBPlusTree(kzg_setup, kzg_utils, root, min_degree, MODULUS, WIDTH)

    # Insert nodes

    values = {}
    for i in range(NUMBER_INITIAL_KEYS):
        key, value = randint(0, KEY_RANGE), randint(0, KEY_RANGE)
        v_bplus_tree.insert_node(int_to_bytes(key), int_to_bytes(value))
        values[key] = value
    
    print("Inserted {0} elements".format(NUMBER_INITIAL_KEYS), file=sys.stderr)

    time_a = time()
    v_bplus_tree.add_node_hash(v_bplus_tree.root)
    time_b = time()

    print("Computed verkle root in {0:.3f} s".format(time_b - time_a), file=sys.stderr)

    if NUMBER_ADDED_KEYS > 0:
        time_a = time()
        v_bplus_tree.check_valid_tree(v_bplus_tree.root)
        time_b = time()

        print("[Checked tree valid: {0:.3f} s]".format(time_b - time_a), file=sys.stderr)

        time_x = time()
        for i in range(NUMBER_ADDED_KEYS):
            key, value = randint(0, KEY_RANGE), randint(0, KEY_RANGE)
            v_bplus_tree.upsert_vc_node(int_to_bytes(key), int_to_bytes(value))
            values[key] = value
        time_y = time()


        print("Additionally inserted {0} elements in {1:.3f} s".format(NUMBER_ADDED_KEYS, time_y - time_x), file=sys.stderr)

        time_a = time()
        v_bplus_tree.check_valid_tree(v_bplus_tree.root)
        time_b = time()
        
        print("[Checked tree valid: {0:.3f} s]".format(time_b - time_a), file=sys.stderr)



    # if NUMBER_DELETED_KEYS > 0:
    #     all_keys = list(values.keys())
    #     shuffle(all_keys)

    #     keys_to_delete = all_keys[:NUMBER_DELETED_KEYS]

    #     time_a = time()
    #     for key in keys_to_delete:
    #         v_bplus_tree.delete_vc_node(int_to_bytes(key))
    #         del values[key]
    #     time_b = time()
        
    #     print("Deleted {0} elements in {1:.3f} s".format(NUMBER_DELETED_KEYS, time_b - time_a), file=sys.stderr)

    #     time_a = time()
    #     v_bplus_tree.check_valid_tree(v_bplus_tree.root)
    #     time_b = time()
        
    #     print("[Checked tree valid: {0:.3f} s]".format(time_b - time_a), file=sys.stderr)
