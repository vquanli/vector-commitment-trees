from src.verkle_trie.v_bst import VBST, VBSTNode, KzgIntegration, int_to_bytes


MODULUS = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
WIDTH = 2
PRIMITIVE_ROOT = 7
SECRET = 8927347823478352432985


class TestVBST:
    kzg_integration = KzgIntegration(MODULUS, WIDTH, PRIMITIVE_ROOT)
    kzg_setup = kzg_integration.generate_setup(WIDTH, SECRET)
    kzg_utils = kzg_integration.kzg_utils(kzg_setup)
    root = VBSTNode(int_to_bytes(100), int_to_bytes(100))
    v_bst = VBST(kzg_setup, kzg_utils, root, MODULUS, WIDTH)

    def test_tree_construction(self):
        v_bst = self.v_bst
        v_bst.insert_node(int_to_bytes(50), int_to_bytes(50))
        v_bst.insert_node(int_to_bytes(150), int_to_bytes(150))
        v_bst.insert_node(int_to_bytes(25), int_to_bytes(25))
        v_bst.insert_node(int_to_bytes(75), int_to_bytes(75))
        v_bst.add_node_hash(v_bst.root)

        tree_structure = v_bst.inorder_tree_structure(v_bst.root)
        assert tree_structure == [{'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '  L1', 'key': 50, 'value': 50},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': 'Root0', 'key': 100, 'value': 100},
                                  {'position': '  R1', 'key': 150, 'value': 150}]

        v_bst.check_valid_tree(v_bst.root)

    def test_upsert_insert(self):
        v_bst = self.v_bst
        v_bst.upsert_vnode(int_to_bytes(60), int_to_bytes(60))
        v_bst.upsert_vnode(int_to_bytes(40), int_to_bytes(40))
        v_bst.upsert_vnode(int_to_bytes(10), int_to_bytes(10))
        v_bst.upsert_vnode(int_to_bytes(20), int_to_bytes(20))
        v_bst.upsert_vnode(int_to_bytes(80), int_to_bytes(80))

        tree_structure = v_bst.inorder_tree_structure(v_bst.root)
        assert tree_structure == [{'position': '      L3', 'key': 10, 'value': 10},
                                  {'position': '        R4', 'key': 20, 'value': 20},
                                  {'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '      R3', 'key': 40, 'value': 40},
                                  {'position': '  L1', 'key': 50, 'value': 50},
                                  {'position': '      L3', 'key': 60, 'value': 60},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': '      R3', 'key': 80, 'value': 80},
                                  {'position': 'Root0', 'key': 100, 'value': 100},
                                  {'position': '  R1', 'key': 150, 'value': 150}]

        v_bst.check_valid_tree(v_bst.root)

    def test_upsert_update(self):
        v_bst = self.v_bst
        v_bst.upsert_vnode(int_to_bytes(50), int_to_bytes(500))
        v_bst.upsert_vnode(int_to_bytes(150), int_to_bytes(1500))

        tree_structure = v_bst.inorder_tree_structure(v_bst.root)
        assert tree_structure == [{'position': '      L3', 'key': 10, 'value': 10},
                                  {'position': '        R4', 'key': 20, 'value': 20},
                                  {'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '      R3', 'key': 40, 'value': 40},
                                  {'position': '  L1', 'key': 50, 'value': 500},
                                  {'position': '      L3', 'key': 60, 'value': 60},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': '      R3', 'key': 80, 'value': 80},
                                  {'position': 'Root0', 'key': 100, 'value': 100},
                                  {'position': '  R1', 'key': 150, 'value': 1500}]

        v_bst.check_valid_tree(v_bst.root)

    def test_upsert_root(self):
        v_bst = self.v_bst
        v_bst.upsert_vnode(int_to_bytes(100), int_to_bytes(1000))

        tree_structure = v_bst.inorder_tree_structure(v_bst.root)
        assert tree_structure == [{'position': '      L3', 'key': 10, 'value': 10},
                                  {'position': '        R4', 'key': 20, 'value': 20},
                                  {'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '      R3', 'key': 40, 'value': 40},
                                  {'position': '  L1', 'key': 50, 'value': 500},
                                  {'position': '      L3', 'key': 60, 'value': 60},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': '      R3', 'key': 80, 'value': 80},
                                  {'position': 'Root0', 'key': 100, 'value': 1000},
                                  {'position': '  R1', 'key': 150, 'value': 1500}]

        v_bst.check_valid_tree(v_bst.root)

    def test_delete_leaf(self):
        v_bst = self.v_bst
        v_bst.delete_vnode(int_to_bytes(80))

        tree_structure = v_bst.inorder_tree_structure(v_bst.root)
        assert tree_structure == [{'position': '      L3', 'key': 10, 'value': 10},
                                  {'position': '        R4', 'key': 20, 'value': 20},
                                  {'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '      R3', 'key': 40, 'value': 40},
                                  {'position': '  L1', 'key': 50, 'value': 500},
                                  {'position': '      L3', 'key': 60, 'value': 60},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': 'Root0', 'key': 100, 'value': 1000},
                                  {'position': '  R1', 'key': 150, 'value': 1500}]

        v_bst.check_valid_tree(v_bst.root)

    def test_delete_single_parent(self):
        v_bst = self.v_bst
        v_bst.delete_vnode(int_to_bytes(10))

        tree_structure = v_bst.inorder_tree_structure(v_bst.root)
        assert tree_structure == [{'position': '      L3', 'key': 20, 'value': 20},
                                  {'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '      R3', 'key': 40, 'value': 40},
                                  {'position': '  L1', 'key': 50, 'value': 500},
                                  {'position': '      L3', 'key': 60, 'value': 60},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': 'Root0', 'key': 100, 'value': 1000},
                                  {'position': '  R1', 'key': 150, 'value': 1500}]

        v_bst.check_valid_tree(v_bst.root)

    def test_delete_full_parent(self):
        v_bst = self.v_bst
        v_bst.delete_vnode(int_to_bytes(50))

        tree_structure = v_bst.inorder_tree_structure(v_bst.root)
        assert tree_structure == [{'position': '      L3', 'key': 20, 'value': 20},
                                  {'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '      R3', 'key': 40, 'value': 40},
                                  {'position': '  L1', 'key': 60, 'value': 60},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': 'Root0', 'key': 100, 'value': 1000},
                                  {'position': '  R1', 'key': 150, 'value': 1500}]

        v_bst.check_valid_tree(v_bst.root)

    def test_delete_root(self):
        v_bst = self.v_bst
        v_bst.delete_vnode(int_to_bytes(100))

        tree_structure = v_bst.inorder_tree_structure(v_bst.root)
        assert tree_structure == [{'position': '      L3', 'key': 20, 'value': 20},
                                  {'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '      R3', 'key': 40, 'value': 40},
                                  {'position': '  L1', 'key': 60, 'value': 60},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': 'Root0', 'key': 150, 'value': 1500}]

        v_bst.check_valid_tree(v_bst.root)




