echo -e "TYPE\tWIDTH_BITS\tWIDTH\tKEY_RANGE\tNUMBER_INITIAL_KEYS\tNUMBER_ADDED_KEYS\ttime_to_insert\tcompute_root\ttime_to_add\tcheck_valid_tree_after_add\tNUMBER_SEARCH_KEYS\ttime_to_search\tNUMBER_DELETED_KEYS\ttime_to_delete\tcheck_valid_tree_after_delete" > evaluation/stats_tree_construct_width.txt

# (WIDTH_BITS, KEY_RANGE, NUMBER_INITIAL_KEYS, NUMBER_ADDED_KEYS, NUMBER_SEARCH_KEYS, NUMBER_DELETED_KEYS)
python vb_tree.py 2 16 12 12 0 >> evaluation/stats_tree_construct_width.txt
python vbplus_tree.py 2 16 12 12 0 >> evaluation/stats_tree_construct_width.txt

python vb_tree.py 3 16 12 12 0 >> evaluation/stats_tree_construct_width.txt
python vbplus_tree.py 3 16 12 12 0 >> evaluation/stats_tree_construct_width.txt

python vb_tree.py 4 16 12 12 0 >> evaluation/stats_tree_construct_width.txt
python vbplus_tree.py 4 16 12 12 0 >> evaluation/stats_tree_construct_width.txt

python vb_tree.py 5 16 12 12 0 >> evaluation/stats_tree_construct_width.txt
python vbplus_tree.py 5 16 12 12 0 >> evaluation/stats_tree_construct_width.txt

python vb_tree.py 6 16 12 12 0 >> evaluation/stats_tree_construct_width.txt
python vbplus_tree.py 6 16 12 12 0 >> evaluation/stats_tree_construct_width.txt

python vb_tree.py 7 16 12 12 0 >> evaluation/stats_tree_construct_width.txt
python vbplus_tree.py 7 16 12 12 0 >> evaluation/stats_tree_construct_width.txt

python vb_tree.py 8 16 12 12 0 >> evaluation/stats_tree_construct_width.txt
python vbplus_tree.py 8 16 12 12 0 >> evaluation/stats_tree_construct_width.txt