from verkle_trie_bst import VerkleBST, VerkleBSTNode, KzgIntegration, int_to_bytes


MODULUS = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
WIDTH = 2
PRIMITIVE_ROOT = 7
SECRET = 8927347823478352432985


class TestVerkleBST:
    kzg_integration = KzgIntegration(MODULUS, WIDTH, PRIMITIVE_ROOT)
    kzg_setup = kzg_integration.generate_setup(WIDTH, SECRET)
    kzg_utils = kzg_integration.kzg_utils(kzg_setup)
    root = VerkleBSTNode(int_to_bytes(100), int_to_bytes(100))
    verkle_bst = VerkleBST(kzg_setup, kzg_utils, root, MODULUS, WIDTH)

    def test_tree_construction(self):
        verkle_bst = self.verkle_bst
        verkle_bst.insert_node(int_to_bytes(50), int_to_bytes(50))
        verkle_bst.insert_node(int_to_bytes(150), int_to_bytes(150))
        verkle_bst.insert_node(int_to_bytes(25), int_to_bytes(25))
        verkle_bst.insert_node(int_to_bytes(75), int_to_bytes(75))
        verkle_bst.add_node_hash(verkle_bst.root)

        tree_structure = verkle_bst.inorder_tree_structure(verkle_bst.root)
        assert tree_structure == [{'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '  L1', 'key': 50, 'value': 50},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': 'Root0', 'key': 100, 'value': 100},
                                  {'position': '  R1', 'key': 150, 'value': 150}]

        verkle_bst.check_valid_tree(verkle_bst.root)

    def test_upsert_insert(self):
        verkle_bst = self.verkle_bst
        verkle_bst.upsert_verkle_node(int_to_bytes(60), int_to_bytes(60))
        verkle_bst.upsert_verkle_node(int_to_bytes(40), int_to_bytes(40))
        verkle_bst.upsert_verkle_node(int_to_bytes(10), int_to_bytes(10))
        verkle_bst.upsert_verkle_node(int_to_bytes(20), int_to_bytes(20))
        verkle_bst.upsert_verkle_node(int_to_bytes(80), int_to_bytes(80))

        tree_structure = verkle_bst.inorder_tree_structure(verkle_bst.root)
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

        verkle_bst.check_valid_tree(verkle_bst.root)

    def test_upsert_update(self):
        verkle_bst = self.verkle_bst
        verkle_bst.upsert_verkle_node(int_to_bytes(50), int_to_bytes(500))
        verkle_bst.upsert_verkle_node(int_to_bytes(150), int_to_bytes(1500))

        tree_structure = verkle_bst.inorder_tree_structure(verkle_bst.root)
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

        verkle_bst.check_valid_tree(verkle_bst.root)

    def test_upsert_root(self):
        verkle_bst = self.verkle_bst
        verkle_bst.upsert_verkle_node(int_to_bytes(100), int_to_bytes(1000))

        tree_structure = verkle_bst.inorder_tree_structure(verkle_bst.root)
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

        verkle_bst.check_valid_tree(verkle_bst.root)

    def test_delete_leaf(self):
        verkle_bst = self.verkle_bst
        verkle_bst.delete_verkle_node(int_to_bytes(80))

        tree_structure = verkle_bst.inorder_tree_structure(verkle_bst.root)
        assert tree_structure == [{'position': '      L3', 'key': 10, 'value': 10},
                                  {'position': '        R4', 'key': 20, 'value': 20},
                                  {'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '      R3', 'key': 40, 'value': 40},
                                  {'position': '  L1', 'key': 50, 'value': 500},
                                  {'position': '      L3', 'key': 60, 'value': 60},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': 'Root0', 'key': 100, 'value': 1000},
                                  {'position': '  R1', 'key': 150, 'value': 1500}]

        verkle_bst.check_valid_tree(verkle_bst.root)

    def test_delete_single_parent(self):
        verkle_bst = self.verkle_bst
        verkle_bst.delete_verkle_node(int_to_bytes(10))

        tree_structure = verkle_bst.inorder_tree_structure(verkle_bst.root)
        assert tree_structure == [{'position': '      L3', 'key': 20, 'value': 20},
                                  {'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '      R3', 'key': 40, 'value': 40},
                                  {'position': '  L1', 'key': 50, 'value': 500},
                                  {'position': '      L3', 'key': 60, 'value': 60},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': 'Root0', 'key': 100, 'value': 1000},
                                  {'position': '  R1', 'key': 150, 'value': 1500}]

        verkle_bst.check_valid_tree(verkle_bst.root)

    def test_delete_full_parent(self):
        verkle_bst = self.verkle_bst
        verkle_bst.delete_verkle_node(int_to_bytes(50))

        tree_structure = verkle_bst.inorder_tree_structure(verkle_bst.root)
        assert tree_structure == [{'position': '      L3', 'key': 20, 'value': 20},
                                  {'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '      R3', 'key': 40, 'value': 40},
                                  {'position': '  L1', 'key': 60, 'value': 60},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': 'Root0', 'key': 100, 'value': 1000},
                                  {'position': '  R1', 'key': 150, 'value': 1500}]

        verkle_bst.check_valid_tree(verkle_bst.root)

    def test_delete_root(self):
        verkle_bst = self.verkle_bst
        verkle_bst.delete_verkle_node(int_to_bytes(100))

        tree_structure = verkle_bst.inorder_tree_structure(verkle_bst.root)
        assert tree_structure == [{'position': '      L3', 'key': 20, 'value': 20},
                                  {'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '      R3', 'key': 40, 'value': 40},
                                  {'position': '  L1', 'key': 60, 'value': 60},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': 'Root0', 'key': 150, 'value': 1500}]

        verkle_bst.check_valid_tree(verkle_bst.root)




