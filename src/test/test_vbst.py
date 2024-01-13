from vbst import VBST, VBSTNode, KzgIntegration, int_to_bytes


MODULUS = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
WIDTH = 2
PRIMITIVE_ROOT = 7
SECRET = 8927347823478352432985


class TestVBST:
    kzg_integration = KzgIntegration(SECRET, MODULUS, WIDTH, PRIMITIVE_ROOT)
    root = VBSTNode(int_to_bytes(100), int_to_bytes(100))
    vbst = VBST(kzg_integration, root)

    def test_tree_construction(self):
        vbst = self.vbst
        vbst.insert_node(int_to_bytes(50), int_to_bytes(50))
        vbst.insert_node(int_to_bytes(150), int_to_bytes(150))
        vbst.insert_node(int_to_bytes(25), int_to_bytes(25))
        vbst.insert_node(int_to_bytes(75), int_to_bytes(75))
        vbst.add_node_hash(vbst.root)

        tree_structure = vbst.tree_structure(vbst.root)
        assert tree_structure == [{'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '  L1', 'key': 50, 'value': 50},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': 'Root0', 'key': 100, 'value': 100},
                                  {'position': '  R1', 'key': 150, 'value': 150}]

        vbst.check_valid_tree(vbst.root)

    def test_upsert_insert(self):
        vbst = self.vbst
        vbst.upsert_vc_node(int_to_bytes(60), int_to_bytes(60))
        vbst.upsert_vc_node(int_to_bytes(40), int_to_bytes(40))
        vbst.upsert_vc_node(int_to_bytes(10), int_to_bytes(10))
        vbst.upsert_vc_node(int_to_bytes(20), int_to_bytes(20))
        vbst.upsert_vc_node(int_to_bytes(80), int_to_bytes(80))

        tree_structure = vbst.tree_structure(vbst.root)
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

        vbst.check_valid_tree(vbst.root)

    def test_upsert_update(self):
        vbst = self.vbst
        vbst.upsert_vc_node(int_to_bytes(50), int_to_bytes(500))
        vbst.upsert_vc_node(int_to_bytes(150), int_to_bytes(1500))

        tree_structure = vbst.tree_structure(vbst.root)
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

        vbst.check_valid_tree(vbst.root)

    def test_upsert_root(self):
        vbst = self.vbst
        vbst.upsert_vc_node(int_to_bytes(100), int_to_bytes(1000))

        tree_structure = vbst.tree_structure(vbst.root)
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

        vbst.check_valid_tree(vbst.root)

    def test_delete_leaf(self):
        vbst = self.vbst
        vbst.delete_vc_node(int_to_bytes(80))

        tree_structure = vbst.tree_structure(vbst.root)
        assert tree_structure == [{'position': '      L3', 'key': 10, 'value': 10},
                                  {'position': '        R4', 'key': 20, 'value': 20},
                                  {'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '      R3', 'key': 40, 'value': 40},
                                  {'position': '  L1', 'key': 50, 'value': 500},
                                  {'position': '      L3', 'key': 60, 'value': 60},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': 'Root0', 'key': 100, 'value': 1000},
                                  {'position': '  R1', 'key': 150, 'value': 1500}]

        vbst.check_valid_tree(vbst.root)

    def test_delete_single_parent(self):
        vbst = self.vbst
        vbst.delete_vc_node(int_to_bytes(10))

        tree_structure = vbst.tree_structure(vbst.root)
        assert tree_structure == [{'position': '      L3', 'key': 20, 'value': 20},
                                  {'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '      R3', 'key': 40, 'value': 40},
                                  {'position': '  L1', 'key': 50, 'value': 500},
                                  {'position': '      L3', 'key': 60, 'value': 60},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': 'Root0', 'key': 100, 'value': 1000},
                                  {'position': '  R1', 'key': 150, 'value': 1500}]

        vbst.check_valid_tree(vbst.root)

    def test_delete_full_parent(self):
        vbst = self.vbst
        vbst.delete_vc_node(int_to_bytes(50))

        tree_structure = vbst.tree_structure(vbst.root)
        assert tree_structure == [{'position': '      L3', 'key': 20, 'value': 20},
                                  {'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '      R3', 'key': 40, 'value': 40},
                                  {'position': '  L1', 'key': 60, 'value': 60},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': 'Root0', 'key': 100, 'value': 1000},
                                  {'position': '  R1', 'key': 150, 'value': 1500}]

        vbst.check_valid_tree(vbst.root)

    def test_delete_root(self):
        vbst = self.vbst
        vbst.delete_vc_node(int_to_bytes(100))

        tree_structure = vbst.tree_structure(vbst.root)
        assert tree_structure == [{'position': '      L3', 'key': 20, 'value': 20},
                                  {'position': '    L2', 'key': 25, 'value': 25},
                                  {'position': '      R3', 'key': 40, 'value': 40},
                                  {'position': '  L1', 'key': 60, 'value': 60},
                                  {'position': '    R2', 'key': 75, 'value': 75},
                                  {'position': 'Root0', 'key': 150, 'value': 1500}]

        vbst.check_valid_tree(vbst.root)




