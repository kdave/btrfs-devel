// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024 Western Digital Corporation.  All rights reserved.
 */
#include <linux/array_size.h>
#include <linux/sizes.h>
#include <linux/btrfs.h>
#include <linux/btrfs_tree.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include "btrfs-tests.h"
#include "../disk-io.h"
#include "../transaction.h"
#include "../volumes.h"
#include "../raid-stripe-tree.h"
#include "../block-group.h"

static struct btrfs_io_context *alloc_dummy_bioc(struct btrfs_fs_info *fs_info,
						 u64 logical, u16 total_stripes)
{
	struct btrfs_io_context *bioc;

	bioc = kzalloc(sizeof(struct btrfs_io_context) +
		       sizeof(struct btrfs_io_stripe) * total_stripes,
		       GFP_KERNEL);

	if (!bioc)
		return NULL;

	refcount_set(&bioc->refs, 1);

	bioc->fs_info = fs_info;
	bioc->replace_stripe_src = -1;
	bioc->full_stripe_logical = (u64)-1;
	bioc->logical = logical;

	return bioc;
}

typedef int (*test_func_t)(struct btrfs_fs_info *);

static int test_stripe_tree_delete_tail(struct btrfs_fs_info *fs_info)
{
	struct btrfs_trans_handle trans;
	struct btrfs_io_context *bioc;
	const u64 map_type = BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_RAID1;
	const int total_stripes = btrfs_bg_type_to_factor(map_type);
	u64 logical = SZ_8K;
	u64 length = SZ_64K;
	int i;
	int ret;

	btrfs_init_dummy_trans(&trans, fs_info);

	bioc = alloc_dummy_bioc(fs_info, logical, total_stripes);
	if (!bioc)
		return -ENOMEM;

	bioc->size = length;
	bioc->map_type = map_type;
	for (i = 0; i < total_stripes; ++i) {
		struct btrfs_device *dev;

		dev = kzalloc(sizeof(struct btrfs_device), GFP_KERNEL);
		if (!dev) {
			ret = -ENOMEM;
			goto out;
		}
		dev->devid = i;
		bioc->stripes[i].dev = dev;
		bioc->stripes[i].length = length;
		bioc->stripes[i].physical = i * SZ_8K;
	}

	ret = btrfs_insert_one_raid_extent(&trans, bioc);
	if (ret)
		goto out;

	ret = btrfs_delete_raid_extent(&trans, logical, SZ_16K);

out:
	for (i = 0; i < total_stripes; i++)
		kfree(bioc->stripes[i].dev);

	kfree(bioc);
	return ret;
}

static int test_stripe_tree_delete_front(struct btrfs_fs_info *fs_info)
{
	struct btrfs_trans_handle trans;
	struct btrfs_io_context *bioc;
	const u64 map_type = BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_RAID1;
	const int total_stripes = btrfs_bg_type_to_factor(map_type);
	u64 logical = SZ_8K;
	u64 length = SZ_64K;
	int i;
	int ret;

	btrfs_init_dummy_trans(&trans, fs_info);

	bioc = alloc_dummy_bioc(fs_info, logical, total_stripes);
	if (!bioc)
		return -ENOMEM;

	bioc->size = length;
	bioc->map_type = map_type;
	for (i = 0; i < total_stripes; i++) {
		struct btrfs_device *dev;

		dev = kzalloc(sizeof(struct btrfs_device), GFP_KERNEL);
		if (!dev) {
			ret = -ENOMEM;
			goto out;
		}
		dev->devid = i;
		bioc->stripes[i].dev = dev;
		bioc->stripes[i].length = length;
		bioc->stripes[i].physical = i * SZ_8K;
	}

	ret = btrfs_insert_one_raid_extent(&trans, bioc);
	if (ret)
		goto out;
	ret = btrfs_delete_raid_extent(&trans, logical, SZ_8K);
out:
	for (i = 0; i < total_stripes; i++)
		kfree(bioc->stripes[i].dev);

	kfree(bioc);
	return ret;

}

static int test_stripe_tree_delete_whole(struct btrfs_fs_info *fs_info)
{
	struct btrfs_trans_handle trans;
	struct btrfs_io_context *bioc;
	const u64 map_type = BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_RAID1;
	const int total_stripes = btrfs_bg_type_to_factor(map_type);
	u64 logical = SZ_8K;
	u64 length = SZ_64K;
	int i;
	int ret;

	btrfs_init_dummy_trans(&trans, fs_info);

	bioc = alloc_dummy_bioc(fs_info, logical, total_stripes);
	if (!bioc)
		return -ENOMEM;

	bioc->size = length;
	bioc->map_type = map_type;
	for (i = 0; i < total_stripes; ++i) {
		struct btrfs_device *dev;

		dev = kzalloc(sizeof(struct btrfs_device), GFP_KERNEL);
		if (!dev) {
			ret = -ENOMEM;
			goto out;
		}
		dev->devid = i;
		bioc->stripes[i].dev = dev;
		bioc->stripes[i].length = length;
		bioc->stripes[i].physical = i * SZ_8K;
	}

	ret = btrfs_insert_one_raid_extent(&trans, bioc);
	if (ret)
		goto out;

	ret = btrfs_delete_raid_extent(&trans, logical, length);

out:
	for (i = 0; i < total_stripes; i++)
		kfree(bioc->stripes[i].dev);

	kfree(bioc);
	return ret;
}

static int test_stripe_tree_delete(struct btrfs_fs_info *fs_info)
{
	test_func_t delete_tests[] = {
		test_stripe_tree_delete_whole,
		test_stripe_tree_delete_front,
		test_stripe_tree_delete_tail,
	};
	int ret;

	for (int i = 0; i < ARRAY_SIZE(delete_tests); i++) {
		test_func_t test = delete_tests[i];

		ret = test(fs_info);
		if (ret)
			goto out;
	}

out:
	return ret;
}

int btrfs_test_raid_stripe_tree(u32 sectorsize, u32 nodesize)
{
	test_func_t tests[] = {
		test_stripe_tree_delete,
	};
	struct btrfs_fs_info *fs_info;
	struct btrfs_root *root = NULL;
	int ret = 0;

	test_msg("running raid-stripe-tree tests");

	fs_info = btrfs_alloc_dummy_fs_info(nodesize, sectorsize);
	if (!fs_info) {
		test_std_err(TEST_ALLOC_FS_INFO);
		ret = -ENOMEM;
		goto out;
	}

	root = btrfs_alloc_dummy_root(fs_info);
	if (IS_ERR(root)) {
		test_std_err(TEST_ALLOC_ROOT);
		ret = PTR_ERR(root);
		goto out;
	}

	btrfs_set_super_incompat_flags(fs_info->super_copy,
				       BTRFS_FEATURE_INCOMPAT_RAID_STRIPE_TREE);
	root->root_key.objectid = BTRFS_RAID_STRIPE_TREE_OBJECTID;
	root->root_key.type = BTRFS_ROOT_ITEM_KEY;
	root->root_key.offset = 0;
	btrfs_global_root_insert(root);
	fs_info->stripe_root = root;

	root->node = alloc_test_extent_buffer(fs_info, nodesize);
	if (IS_ERR(root->node)) {
		test_std_err(TEST_ALLOC_EXTENT_BUFFER);
		ret = PTR_ERR(root->node);
		goto out;
	}
	btrfs_set_header_level(root->node, 0);
	btrfs_set_header_nritems(root->node, 0);
	root->alloc_bytenr += 2 * nodesize;

	for (int i = 0; i < ARRAY_SIZE(tests); i++) {
		test_func_t test = tests[i];

		ret = test(fs_info);
		if (ret)
			goto out;
	}
out:
	btrfs_free_dummy_root(root);
	btrfs_free_dummy_fs_info(fs_info);
	return ret;
}
