/*
 * Copyright (C) 2007 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/buffer_head.h>
#include <linux/kobject.h>
#include <linux/bug.h>
#include <linux/genhd.h>
#include <linux/debugfs.h>

#include "ctree.h"
#include "disk-io.h"
#include "transaction.h"
#include "sysfs.h"
#include "volumes.h"
#include "rcu-string.h"

static inline struct btrfs_fs_info *to_fs_info(struct kobject *kobj);
static inline struct btrfs_fs_devices *to_fs_devs(struct kobject *kobj);
static inline struct btrfs_device *to_btrfs_dev(struct kobject *kobj);

static u64 get_features(struct btrfs_fs_info *fs_info,
			enum btrfs_feature_set set)
{
	struct btrfs_super_block *disk_super = fs_info->super_copy;
	if (set == FEAT_COMPAT)
		return btrfs_super_compat_flags(disk_super);
	else if (set == FEAT_COMPAT_RO)
		return btrfs_super_compat_ro_flags(disk_super);
	else
		return btrfs_super_incompat_flags(disk_super);
}

static void set_features(struct btrfs_fs_info *fs_info,
			 enum btrfs_feature_set set, u64 features)
{
	struct btrfs_super_block *disk_super = fs_info->super_copy;
	if (set == FEAT_COMPAT)
		btrfs_set_super_compat_flags(disk_super, features);
	else if (set == FEAT_COMPAT_RO)
		btrfs_set_super_compat_ro_flags(disk_super, features);
	else
		btrfs_set_super_incompat_flags(disk_super, features);
}

static int can_modify_feature(struct btrfs_feature_attr *fa)
{
	int val = 0;
	u64 set, clear;
	switch (fa->feature_set) {
	case FEAT_COMPAT:
		set = BTRFS_FEATURE_COMPAT_SAFE_SET;
		clear = BTRFS_FEATURE_COMPAT_SAFE_CLEAR;
		break;
	case FEAT_COMPAT_RO:
		set = BTRFS_FEATURE_COMPAT_RO_SAFE_SET;
		clear = BTRFS_FEATURE_COMPAT_RO_SAFE_CLEAR;
		break;
	case FEAT_INCOMPAT:
		set = BTRFS_FEATURE_INCOMPAT_SAFE_SET;
		clear = BTRFS_FEATURE_INCOMPAT_SAFE_CLEAR;
		break;
	default:
		printk(KERN_WARNING "btrfs: sysfs: unknown feature set %d\n",
				fa->feature_set);
		return 0;
	}

	if (set & fa->feature_bit)
		val |= 1;
	if (clear & fa->feature_bit)
		val |= 2;

	return val;
}

static ssize_t btrfs_feature_attr_show(struct kobject *kobj,
				       struct kobj_attribute *a, char *buf)
{
	int val = 0;
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	struct btrfs_feature_attr *fa = to_btrfs_feature_attr(a);
	if (fs_info) {
		u64 features = get_features(fs_info, fa->feature_set);
		if (features & fa->feature_bit)
			val = 1;
	} else
		val = can_modify_feature(fa);

	return snprintf(buf, PAGE_SIZE, "%d\n", val);
}

static ssize_t btrfs_feature_attr_store(struct kobject *kobj,
					struct kobj_attribute *a,
					const char *buf, size_t count)
{
	struct btrfs_fs_info *fs_info;
	struct btrfs_feature_attr *fa = to_btrfs_feature_attr(a);
	u64 features, set, clear;
	unsigned long val;
	int ret;

	fs_info = to_fs_info(kobj);
	if (!fs_info)
		return -EPERM;

	ret = kstrtoul(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;

	if (fa->feature_set == FEAT_COMPAT) {
		set = BTRFS_FEATURE_COMPAT_SAFE_SET;
		clear = BTRFS_FEATURE_COMPAT_SAFE_CLEAR;
	} else if (fa->feature_set == FEAT_COMPAT_RO) {
		set = BTRFS_FEATURE_COMPAT_RO_SAFE_SET;
		clear = BTRFS_FEATURE_COMPAT_RO_SAFE_CLEAR;
	} else {
		set = BTRFS_FEATURE_INCOMPAT_SAFE_SET;
		clear = BTRFS_FEATURE_INCOMPAT_SAFE_CLEAR;
	}

	features = get_features(fs_info, fa->feature_set);

	/* Nothing to do */
	if ((val && (features & fa->feature_bit)) ||
	    (!val && !(features & fa->feature_bit)))
		return count;

	if ((val && !(set & fa->feature_bit)) ||
	    (!val && !(clear & fa->feature_bit))) {
		btrfs_info(fs_info,
			"%sabling feature %s on mounted fs is not supported.",
			val ? "En" : "Dis", fa->kobj_attr.attr.name);
		return -EPERM;
	}

	btrfs_info(fs_info, "%s %s feature flag",
		   val ? "Setting" : "Clearing", fa->kobj_attr.attr.name);

	spin_lock(&fs_info->super_lock);
	features = get_features(fs_info, fa->feature_set);
	if (val)
		features |= fa->feature_bit;
	else
		features &= ~fa->feature_bit;
	set_features(fs_info, fa->feature_set, features);
	spin_unlock(&fs_info->super_lock);

	/*
	 * We don't want to do full transaction commit from inside sysfs
	 */
	btrfs_set_pending(fs_info, COMMIT);
	wake_up_process(fs_info->transaction_kthread);

	return count;
}

static umode_t btrfs_feature_visible(struct kobject *kobj,
				     struct attribute *attr, int unused)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	umode_t mode = attr->mode;

	if (fs_info) {
		struct btrfs_feature_attr *fa;
		u64 features;

		fa = attr_to_btrfs_feature_attr(attr);
		features = get_features(fs_info, fa->feature_set);

		if (can_modify_feature(fa))
			mode |= S_IWUSR;
		else if (!(features & fa->feature_bit))
			mode = 0;
	}

	return mode;
}

BTRFS_FEAT_ATTR_INCOMPAT(mixed_backref, MIXED_BACKREF);
BTRFS_FEAT_ATTR_INCOMPAT(default_subvol, DEFAULT_SUBVOL);
BTRFS_FEAT_ATTR_INCOMPAT(mixed_groups, MIXED_GROUPS);
BTRFS_FEAT_ATTR_INCOMPAT(compress_lzo, COMPRESS_LZO);
BTRFS_FEAT_ATTR_INCOMPAT(big_metadata, BIG_METADATA);
BTRFS_FEAT_ATTR_INCOMPAT(extended_iref, EXTENDED_IREF);
BTRFS_FEAT_ATTR_INCOMPAT(raid56, RAID56);
BTRFS_FEAT_ATTR_INCOMPAT(skinny_metadata, SKINNY_METADATA);
BTRFS_FEAT_ATTR_INCOMPAT(no_holes, NO_HOLES);

static struct attribute *btrfs_supported_feature_attrs[] = {
	BTRFS_FEAT_ATTR_PTR(mixed_backref),
	BTRFS_FEAT_ATTR_PTR(default_subvol),
	BTRFS_FEAT_ATTR_PTR(mixed_groups),
	BTRFS_FEAT_ATTR_PTR(compress_lzo),
	BTRFS_FEAT_ATTR_PTR(big_metadata),
	BTRFS_FEAT_ATTR_PTR(extended_iref),
	BTRFS_FEAT_ATTR_PTR(raid56),
	BTRFS_FEAT_ATTR_PTR(skinny_metadata),
	BTRFS_FEAT_ATTR_PTR(no_holes),
	NULL
};

static const struct attribute_group btrfs_feature_attr_group = {
	.name = "features",
	.is_visible = btrfs_feature_visible,
	.attrs = btrfs_supported_feature_attrs,
};

static ssize_t btrfs_show_u64(u64 *value_ptr, spinlock_t *lock, char *buf)
{
	u64 val;
	if (lock)
		spin_lock(lock);
	val = *value_ptr;
	if (lock)
		spin_unlock(lock);
	return snprintf(buf, PAGE_SIZE, "%llu\n", val);
}

static ssize_t global_rsv_size_show(struct kobject *kobj,
				    struct kobj_attribute *ka, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj->parent);
	struct btrfs_block_rsv *block_rsv = &fs_info->global_block_rsv;
	return btrfs_show_u64(&block_rsv->size, &block_rsv->lock, buf);
}
BTRFS_ATTR(global_rsv_size, global_rsv_size_show);

static ssize_t global_rsv_reserved_show(struct kobject *kobj,
					struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj->parent);
	struct btrfs_block_rsv *block_rsv = &fs_info->global_block_rsv;
	return btrfs_show_u64(&block_rsv->reserved, &block_rsv->lock, buf);
}
BTRFS_ATTR(global_rsv_reserved, global_rsv_reserved_show);

#define to_space_info(_kobj) container_of(_kobj, struct btrfs_space_info, kobj)
#define to_raid_kobj(_kobj) container_of(_kobj, struct raid_kobject, kobj)

static ssize_t raid_bytes_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf);
BTRFS_RAID_ATTR(total_bytes, raid_bytes_show);
BTRFS_RAID_ATTR(used_bytes, raid_bytes_show);

static ssize_t raid_bytes_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)

{
	struct btrfs_space_info *sinfo = to_space_info(kobj->parent);
	struct btrfs_block_group_cache *block_group;
	int index = to_raid_kobj(kobj)->raid_type;
	u64 val = 0;

	down_read(&sinfo->groups_sem);
	list_for_each_entry(block_group, &sinfo->block_groups[index], list) {
		if (&attr->attr == BTRFS_RAID_ATTR_PTR(total_bytes))
			val += block_group->key.offset;
		else
			val += btrfs_block_group_used(&block_group->item);
	}
	up_read(&sinfo->groups_sem);
	return snprintf(buf, PAGE_SIZE, "%llu\n", val);
}

static struct attribute *raid_attributes[] = {
	BTRFS_RAID_ATTR_PTR(total_bytes),
	BTRFS_RAID_ATTR_PTR(used_bytes),
	NULL
};

static void release_raid_kobj(struct kobject *kobj)
{
	kfree(to_raid_kobj(kobj));
}

struct kobj_type btrfs_raid_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = release_raid_kobj,
	.default_attrs = raid_attributes,
};

#define SPACE_INFO_ATTR(field)						\
static ssize_t btrfs_space_info_show_##field(struct kobject *kobj,	\
					     struct kobj_attribute *a,	\
					     char *buf)			\
{									\
	struct btrfs_space_info *sinfo = to_space_info(kobj);		\
	return btrfs_show_u64(&sinfo->field, &sinfo->lock, buf);	\
}									\
BTRFS_ATTR(field, btrfs_space_info_show_##field)

static ssize_t btrfs_space_info_show_total_bytes_pinned(struct kobject *kobj,
						       struct kobj_attribute *a,
						       char *buf)
{
	struct btrfs_space_info *sinfo = to_space_info(kobj);
	s64 val = percpu_counter_sum(&sinfo->total_bytes_pinned);
	return snprintf(buf, PAGE_SIZE, "%lld\n", val);
}

SPACE_INFO_ATTR(flags);
SPACE_INFO_ATTR(total_bytes);
SPACE_INFO_ATTR(bytes_used);
SPACE_INFO_ATTR(bytes_pinned);
SPACE_INFO_ATTR(bytes_reserved);
SPACE_INFO_ATTR(bytes_may_use);
SPACE_INFO_ATTR(disk_used);
SPACE_INFO_ATTR(disk_total);
BTRFS_ATTR(total_bytes_pinned, btrfs_space_info_show_total_bytes_pinned);

static struct attribute *space_info_attrs[] = {
	BTRFS_ATTR_PTR(flags),
	BTRFS_ATTR_PTR(total_bytes),
	BTRFS_ATTR_PTR(bytes_used),
	BTRFS_ATTR_PTR(bytes_pinned),
	BTRFS_ATTR_PTR(bytes_reserved),
	BTRFS_ATTR_PTR(bytes_may_use),
	BTRFS_ATTR_PTR(disk_used),
	BTRFS_ATTR_PTR(disk_total),
	BTRFS_ATTR_PTR(total_bytes_pinned),
	NULL,
};

static void space_info_release(struct kobject *kobj)
{
	struct btrfs_space_info *sinfo = to_space_info(kobj);
	percpu_counter_destroy(&sinfo->total_bytes_pinned);
	kfree(sinfo);
}

struct kobj_type space_info_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = space_info_release,
	.default_attrs = space_info_attrs,
};

static const struct attribute *allocation_attrs[] = {
	BTRFS_ATTR_PTR(global_rsv_reserved),
	BTRFS_ATTR_PTR(global_rsv_size),
	NULL,
};

static ssize_t btrfs_label_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	char *label = fs_info->super_copy->label;
	return snprintf(buf, PAGE_SIZE, label[0] ? "%s\n" : "%s", label);
}

static ssize_t btrfs_label_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	size_t p_len;

	if (fs_info->sb->s_flags & MS_RDONLY)
		return -EROFS;

	/*
	 * p_len is the len until the first occurrence of either
	 * '\n' or '\0'
	 */
	p_len = strcspn(buf, "\n");

	if (p_len >= BTRFS_LABEL_SIZE)
		return -EINVAL;

	spin_lock(&fs_info->super_lock);
	memset(fs_info->super_copy->label, 0, BTRFS_LABEL_SIZE);
	memcpy(fs_info->super_copy->label, buf, p_len);
	spin_unlock(&fs_info->super_lock);

	/*
	 * We don't want to do full transaction commit from inside sysfs
	 */
	btrfs_set_pending(fs_info, COMMIT);
	wake_up_process(fs_info->transaction_kthread);

	return len;
}
BTRFS_ATTR_RW(label, btrfs_label_show, btrfs_label_store);

static ssize_t btrfs_nodesize_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", fs_info->super_copy->nodesize);
}

BTRFS_ATTR(nodesize, btrfs_nodesize_show);

static ssize_t btrfs_sectorsize_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", fs_info->super_copy->sectorsize);
}

BTRFS_ATTR(sectorsize, btrfs_sectorsize_show);

static ssize_t btrfs_clone_alignment_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", fs_info->super_copy->sectorsize);
}

BTRFS_ATTR(clone_alignment, btrfs_clone_alignment_show);

static const struct attribute *btrfs_attrs[] = {
	BTRFS_ATTR_PTR(label),
	BTRFS_ATTR_PTR(nodesize),
	BTRFS_ATTR_PTR(sectorsize),
	BTRFS_ATTR_PTR(clone_alignment),
	NULL,
};

static void btrfs_release_fsid_kobj(struct kobject *kobj)
{
	struct btrfs_fs_devices *fs_devs = to_fs_devs(kobj);

	memset(&fs_devs->fsid_kobj, 0, sizeof(struct kobject));
	complete(&fs_devs->kobj_unregister);
}

static struct kobj_type btrfs_ktype = {
	.sysfs_ops	= &kobj_sysfs_ops,
	.release	= btrfs_release_fsid_kobj,
};

static inline struct btrfs_fs_devices *to_fs_devs(struct kobject *kobj)
{
	if (kobj->ktype != &btrfs_ktype)
		return NULL;
	return container_of(kobj, struct btrfs_fs_devices, fsid_kobj);
}

static inline struct btrfs_fs_info *to_fs_info(struct kobject *kobj)
{
	if (kobj->ktype != &btrfs_ktype)
		return NULL;
	return to_fs_devs(kobj)->fs_info;
}

#define NUM_FEATURE_BITS 64
static char btrfs_unknown_feature_names[3][NUM_FEATURE_BITS][13];
static struct btrfs_feature_attr btrfs_feature_attrs[3][NUM_FEATURE_BITS];

static const u64 supported_feature_masks[3] = {
	[FEAT_COMPAT]    = BTRFS_FEATURE_COMPAT_SUPP,
	[FEAT_COMPAT_RO] = BTRFS_FEATURE_COMPAT_RO_SUPP,
	[FEAT_INCOMPAT]  = BTRFS_FEATURE_INCOMPAT_SUPP,
};

static int addrm_unknown_feature_attrs(struct btrfs_fs_info *fs_info, bool add)
{
	int set;

	for (set = 0; set < FEAT_MAX; set++) {
		int i;
		struct attribute *attrs[2];
		struct attribute_group agroup = {
			.name = "features",
			.attrs = attrs,
		};
		u64 features = get_features(fs_info, set);
		features &= ~supported_feature_masks[set];

		if (!features)
			continue;

		attrs[1] = NULL;
		for (i = 0; i < NUM_FEATURE_BITS; i++) {
			struct btrfs_feature_attr *fa;

			if (!(features & (1ULL << i)))
				continue;

			fa = &btrfs_feature_attrs[set][i];
			attrs[0] = &fa->kobj_attr.attr;
			if (add) {
				int ret;
				ret = sysfs_merge_group(&fs_info->fs_devices->fsid_kobj,
							&agroup);
				if (ret)
					return ret;
			} else
				sysfs_unmerge_group(&fs_info->fs_devices->fsid_kobj,
						    &agroup);
		}

	}
	return 0;
}

static void __btrfs_sysfs_remove_fsid(struct btrfs_fs_devices *fs_devs)
{
	if (fs_devs->seed) {
		__btrfs_sysfs_remove_fsid(fs_devs->seed);
		btrfs_sysfs_rm_seed_dir(fs_devs);
	}

	if (fs_devs->device_dir_kobj) {
		btrfs_sysfs_rm_devices_attr(fs_devs);
		kobject_del(fs_devs->device_dir_kobj);
		kobject_put(fs_devs->device_dir_kobj);
		fs_devs->device_dir_kobj = NULL;
	}

	if (fs_devs->fsid_kobj.state_initialized) {
		btrfs_sysfs_rm_fsid_attr(fs_devs);
		kobject_del(&fs_devs->fsid_kobj);
		kobject_put(&fs_devs->fsid_kobj);
		wait_for_completion(&fs_devs->kobj_unregister);
	}
}

/* when fs_devs is NULL it will remove all fsid kobject */
void btrfs_sysfs_remove_fsid(struct btrfs_fs_devices *fs_devs)
{
	struct list_head *fs_uuids = btrfs_get_fs_uuids();

	if (fs_devs) {
		__btrfs_sysfs_remove_fsid(fs_devs);
		return;
	}

	list_for_each_entry(fs_devs, fs_uuids, list) {
		__btrfs_sysfs_remove_fsid(fs_devs);
	}
}

void btrfs_sysfs_remove_mounted(struct btrfs_fs_info *fs_info)
{
	btrfs_reset_fs_info_ptr(fs_info);

	if (fs_info->space_info_kobj) {
		sysfs_remove_files(fs_info->space_info_kobj, allocation_attrs);
		kobject_del(fs_info->space_info_kobj);
		kobject_put(fs_info->space_info_kobj);
	}
	addrm_unknown_feature_attrs(fs_info, false);
	sysfs_remove_group(&fs_info->fs_devices->fsid_kobj, &btrfs_feature_attr_group);
	sysfs_remove_files(&fs_info->fs_devices->fsid_kobj, btrfs_attrs);
	btrfs_sysfs_rm_device_link(fs_info->fs_devices, NULL, 1);
	btrfs_sysfs_update_fsid_devices_attr(fs_info->fs_devices, 1);
}

const char * const btrfs_feature_set_names[3] = {
	[FEAT_COMPAT]	 = "compat",
	[FEAT_COMPAT_RO] = "compat_ro",
	[FEAT_INCOMPAT]	 = "incompat",
};

char *btrfs_printable_features(enum btrfs_feature_set set, u64 flags)
{
	size_t bufsize = 4096; /* safe max, 64 names * 64 bytes */
	int len = 0;
	int i;
	char *str;

	str = kmalloc(bufsize, GFP_KERNEL);
	if (!str)
		return str;

	for (i = 0; i < ARRAY_SIZE(btrfs_feature_attrs[set]); i++) {
		const char *name;

		if (!(flags & (1ULL << i)))
			continue;

		name = btrfs_feature_attrs[set][i].kobj_attr.attr.name;
		len += snprintf(str + len, bufsize - len, "%s%s",
				len ? "," : "", name);
	}

	return str;
}

static void init_feature_attrs(void)
{
	struct btrfs_feature_attr *fa;
	int set, i;

	BUILD_BUG_ON(ARRAY_SIZE(btrfs_unknown_feature_names) !=
		     ARRAY_SIZE(btrfs_feature_attrs));
	BUILD_BUG_ON(ARRAY_SIZE(btrfs_unknown_feature_names[0]) !=
		     ARRAY_SIZE(btrfs_feature_attrs[0]));

	memset(btrfs_feature_attrs, 0, sizeof(btrfs_feature_attrs));
	memset(btrfs_unknown_feature_names, 0,
	       sizeof(btrfs_unknown_feature_names));

	for (i = 0; btrfs_supported_feature_attrs[i]; i++) {
		struct btrfs_feature_attr *sfa;
		struct attribute *a = btrfs_supported_feature_attrs[i];
		int bit;
		sfa = attr_to_btrfs_feature_attr(a);
		bit = ilog2(sfa->feature_bit);
		fa = &btrfs_feature_attrs[sfa->feature_set][bit];

		fa->kobj_attr.attr.name = sfa->kobj_attr.attr.name;
	}

	for (set = 0; set < FEAT_MAX; set++) {
		for (i = 0; i < ARRAY_SIZE(btrfs_feature_attrs[set]); i++) {
			char *name = btrfs_unknown_feature_names[set][i];
			fa = &btrfs_feature_attrs[set][i];

			if (fa->kobj_attr.attr.name)
				continue;

			snprintf(name, 13, "%s:%u",
				 btrfs_feature_set_names[set], i);

			fa->kobj_attr.attr.name = name;
			fa->kobj_attr.attr.mode = S_IRUGO;
			fa->feature_set = set;
			fa->feature_bit = 1ULL << i;
		}
	}
}

/* when one_device is NULL, it removes all device links */

int btrfs_sysfs_rm_device_link(struct btrfs_fs_devices *fs_devices,
		struct btrfs_device *one_device, int follow_seed)
{
	struct hd_struct *disk;
	struct kobject *disk_kobj;

	if (!fs_devices->device_dir_kobj)
		return -EINVAL;

	if (one_device && one_device->bdev) {
		disk = one_device->bdev->bd_part;
		disk_kobj = &part_to_dev(disk)->kobj;

		sysfs_remove_link(fs_devices->device_dir_kobj,
						disk_kobj->name);
	}

	if (one_device)
		return 0;

	list_for_each_entry(one_device,
			&fs_devices->devices, dev_list) {
		if (!one_device->bdev)
			continue;
		disk = one_device->bdev->bd_part;
		disk_kobj = &part_to_dev(disk)->kobj;

		sysfs_remove_link(fs_devices->device_dir_kobj,
						disk_kobj->name);
	}

	if (follow_seed && fs_devices->seed)
		btrfs_sysfs_rm_device_link(fs_devices->seed, NULL, follow_seed);

	return 0;
}

int btrfs_sysfs_add_device(struct btrfs_fs_devices *fs_devs)
{
	if (!fs_devs->device_dir_kobj)
		fs_devs->device_dir_kobj = kobject_create_and_add(
					"devices", &fs_devs->fsid_kobj);

	if (!fs_devs->device_dir_kobj)
		return -ENOMEM;

	BUG_ON(!fs_devs->device_dir_kobj->state_initialized);

	return 0;
}

int btrfs_sysfs_add_device_link(struct btrfs_fs_devices *fs_devices,
			struct btrfs_device *one_device, int follow_seed)
{
	int error = 0;
	struct btrfs_device *dev;

again:
	list_for_each_entry(dev, &fs_devices->devices, dev_list) {
		struct hd_struct *disk;
		struct kobject *disk_kobj;

		if (!dev->bdev)
			continue;

		if (one_device && one_device != dev)
			continue;

		disk = dev->bdev->bd_part;
		disk_kobj = &part_to_dev(disk)->kobj;

		error = sysfs_create_link(fs_devices->device_dir_kobj,
					  disk_kobj, disk_kobj->name);
		if (error)
			break;
	}

	if (follow_seed && fs_devices->seed) {
		fs_devices = fs_devices->seed;
		goto again;
	}

	return error;
}

void btrfs_sysfs_rm_seed_dir(struct btrfs_fs_devices *fs_devs)
{
	if (fs_devs->seed_dir_kobj) {
		kobject_del(fs_devs->seed_dir_kobj);
		kobject_put(fs_devs->seed_dir_kobj);
		fs_devs->seed_dir_kobj = NULL;
	}
}

int btrfs_sysfs_add_seed_dir(struct btrfs_fs_devices *fs_devs)
{
	if (!fs_devs->seed_dir_kobj)
		fs_devs->seed_dir_kobj = kobject_create_and_add(
					"seed", &fs_devs->fsid_kobj);

	if (!fs_devs->seed_dir_kobj)
		return -ENOMEM;

	BUG_ON(!fs_devs->seed_dir_kobj->state_initialized);

	return 0;
}

/* /sys/fs/btrfs/ entry */
static struct kset *btrfs_kset;

/* /sys/kernel/debug/btrfs */
static struct dentry *btrfs_debugfs_root_dentry;

/* Debugging tunables and exported data */
u64 btrfs_debugfs_test;

/*
 * Can be called by the device discovery thread.
 * And parent can be specified for seed device
 */
int btrfs_sysfs_add_fsid(struct btrfs_fs_devices *fs_devs,
					struct kobject *parent)
{
	int error = 0;

	if (!fs_devs->fsid_kobj.state_initialized) {
		init_completion(&fs_devs->kobj_unregister);
		fs_devs->fsid_kobj.kset = btrfs_kset;
		error = kobject_init_and_add(&fs_devs->fsid_kobj,
			&btrfs_ktype, parent, "%pU", fs_devs->fsid);
		error = btrfs_sysfs_add_fsid_attr(fs_devs);
	} else {
		error = -EEXIST;
	}
	return error;
}

int btrfs_sysfs_add_mounted(struct btrfs_fs_info *fs_info)
{
	int error;
	struct btrfs_fs_devices *fs_devs = fs_info->fs_devices;
	struct kobject *fsid_kobj = &fs_devs->fsid_kobj;

	btrfs_set_fs_info_ptr(fs_info);

	error = btrfs_sysfs_add_device_link(fs_devs, NULL, 1);
	if (error)
		return error;

	error = sysfs_create_files(fsid_kobj, btrfs_attrs);
	if (error) {
		btrfs_sysfs_rm_device_link(fs_devs, NULL, 0);
		return error;
	}

	btrfs_sysfs_update_fsid_devices_attr(fs_devs, 1);

	error = sysfs_create_group(fsid_kobj,
				   &btrfs_feature_attr_group);
	if (error)
		goto failure;

	error = addrm_unknown_feature_attrs(fs_info, true);
	if (error)
		goto failure;

	fs_info->space_info_kobj = kobject_create_and_add("allocation",
						  fsid_kobj);
	if (!fs_info->space_info_kobj) {
		error = -ENOMEM;
		goto failure;
	}

	error = sysfs_create_files(fs_info->space_info_kobj, allocation_attrs);
	if (error)
		goto failure;

	return 0;
failure:
	btrfs_sysfs_remove_mounted(fs_info);
	return error;
}

static int btrfs_init_debugfs(void)
{
#ifdef CONFIG_DEBUG_FS
	btrfs_debugfs_root_dentry = debugfs_create_dir("btrfs", NULL);
	if (!btrfs_debugfs_root_dentry)
		return -ENOMEM;

	debugfs_create_u64("test", S_IRUGO | S_IWUGO, btrfs_debugfs_root_dentry,
			&btrfs_debugfs_test);
#endif
	return 0;
}

int btrfs_init_sysfs(void)
{
	int ret;

	btrfs_kset = kset_create_and_add("btrfs", NULL, fs_kobj);
	if (!btrfs_kset)
		return -ENOMEM;

	ret = btrfs_init_debugfs();
	if (ret)
		goto out1;

	init_feature_attrs();
	ret = sysfs_create_group(&btrfs_kset->kobj, &btrfs_feature_attr_group);
	if (ret)
		goto out2;

	return 0;
out2:
	debugfs_remove_recursive(btrfs_debugfs_root_dentry);
out1:
	kset_unregister(btrfs_kset);

	return ret;
}

void btrfs_exit_sysfs(void)
{
	sysfs_remove_group(&btrfs_kset->kobj, &btrfs_feature_attr_group);
	btrfs_sysfs_remove_fsid(NULL);
	kset_unregister(btrfs_kset);
	debugfs_remove_recursive(btrfs_debugfs_root_dentry);
}

void btrfs_sysfs_prepare_sprout_reset(void)
{
	/* close call would anyway cleanup */
}

void btrfs_sysfs_prepare_sprout(struct btrfs_fs_devices *fs_devices,
				struct btrfs_fs_devices *seed_devices,
				struct btrfs_fs_devices *old_devices)
{
	char fsid_buf[BTRFS_UUID_UNPARSED_SIZE];

	/*
	 * Sprouting has changed fsid of the mounted root,
	 * so rename the fsid on the sysfs
	 */
	snprintf(fsid_buf, BTRFS_UUID_UNPARSED_SIZE, "%pU", fs_devices->fsid);
	if (kobject_rename(&fs_devices->fsid_kobj, fsid_buf)) {
		pr_warn("Btrfs: sysfs: kobject rename failed\n");
	}

	/*
	 * Create the seed fsid inside the sprout fsid
	 * but should not create devices dir, instead
	 * move it from the original fs_devices
	 */
	memset(&seed_devices->fsid_kobj, 0, sizeof(struct kobject));
	seed_devices->device_dir_kobj = NULL;
	memset(&seed_devices->kobj_unregister, 0,
					sizeof(struct completion));
	seed_devices->seed_dir_kobj = NULL;

	if (!fs_devices->seed_dir_kobj)
		btrfs_sysfs_add_seed_dir(fs_devices);

	btrfs_sysfs_add_fsid(seed_devices, fs_devices->seed_dir_kobj);

	if (kobject_move(fs_devices->device_dir_kobj,
					&seed_devices->fsid_kobj))
		pr_warn("Btrfs: sysfs: dev kobject move failed\n");

	seed_devices->device_dir_kobj = fs_devices->device_dir_kobj;
	fs_devices->device_dir_kobj = NULL;
	btrfs_sysfs_add_device(fs_devices);

	/*
	 * the kobj dev and devices attribute will be created
	 * in the main function as part of the init_new_device
	 * If this is a nested seed, that is if there is seed's
	 * seed device then move that one level deep.
	 */
	if (seed_devices->seed) {
		btrfs_sysfs_add_seed_dir(seed_devices);
		if (kobject_move(&seed_devices->seed->fsid_kobj,
					seed_devices->seed_dir_kobj))
			pr_warn("Btrfs: sysfs: kobject move failed\n");
	}

	btrfs_sysfs_add_fsid(old_devices, NULL);
	btrfs_sysfs_add_device(old_devices);
	btrfs_sysfs_add_devices_attr(old_devices);
}


static ssize_t btrfs_show_uuid(u8 *valptr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%pU\n", valptr);
}

static ssize_t btrfs_show_str(char *strptr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", strptr);
}

static ssize_t btrfs_show_u(uint val, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t btrfs_show_d(int val, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", val);
}


/* btrfs_fs_devices attributes */
struct btrfs_fs_devs_attr {
	struct kobj_attribute kobj_attr;
};

static ssize_t btrfs_fs_devs_attr_show(struct kobject *kobj,
				       struct kobj_attribute *a, char *buf);

static ssize_t btrfs_fs_devs_attr_store(struct kobject *kobj,
					struct kobj_attribute *a,
					const char *buf, size_t count);

#define BTRFS_FS_DEV_ATTR(_name)\
	static struct btrfs_fs_devs_attr btrfs_fs_devs_attr_##_name = {\
		.kobj_attr = __INIT_KOBJ_ATTR(_name, S_IRUGO,\
					btrfs_fs_devs_attr_show,\
					btrfs_fs_devs_attr_store),\
	}

BTRFS_FS_DEV_ATTR(fsid);
BTRFS_FS_DEV_ATTR(num_devices);
BTRFS_FS_DEV_ATTR(open_devices);
BTRFS_FS_DEV_ATTR(rw_devices);
BTRFS_FS_DEV_ATTR(missing_devices);
BTRFS_FS_DEV_ATTR(total_rw_bytes);
BTRFS_FS_DEV_ATTR(total_devices);
BTRFS_FS_DEV_ATTR(opened);
BTRFS_FS_DEV_ATTR(seeding);
BTRFS_FS_DEV_ATTR(rotating);

#define BTRFS_FS_DEV_ATTR_PTR(_name)\
	(&btrfs_fs_devs_attr_##_name.kobj_attr.attr)

static struct attribute *btrfs_fs_devs_attrs[] = {
	BTRFS_FS_DEV_ATTR_PTR(fsid),
	BTRFS_FS_DEV_ATTR_PTR(num_devices),
	BTRFS_FS_DEV_ATTR_PTR(open_devices),
	BTRFS_FS_DEV_ATTR_PTR(rw_devices),
	BTRFS_FS_DEV_ATTR_PTR(missing_devices),
	BTRFS_FS_DEV_ATTR_PTR(total_rw_bytes),
	BTRFS_FS_DEV_ATTR_PTR(total_devices),
	BTRFS_FS_DEV_ATTR_PTR(opened),
	BTRFS_FS_DEV_ATTR_PTR(seeding),
	BTRFS_FS_DEV_ATTR_PTR(rotating),
	NULL
};

#define BTRFS_FS_DEVS_GET_ATTR_UUID(attr, name, valprt, buf)\
	if (attr == BTRFS_FS_DEV_ATTR_PTR(name))\
		return btrfs_show_uuid(valprt, buf)
#define BTRFS_FS_DEVS_GET_ATTR_STR(attr, name, strprt, buf)\
	if (attr == BTRFS_FS_DEV_ATTR_PTR(name))\
		return btrfs_show_str(strprt, buf)
#define BTRFS_FS_DEVS_GET_ATTR_U64(attr, name, valprt, buf)\
	if (attr == BTRFS_FS_DEV_ATTR_PTR(name))\
		return btrfs_show_u64(valprt, NULL, buf)
#define BTRFS_FS_DEVS_GET_ATTR_U(attr, name, val, buf)\
	if (attr == BTRFS_FS_DEV_ATTR_PTR(name))\
		return btrfs_show_u(val, buf)
#define BTRFS_FS_DEVS_GET_ATTR_D(attr, name, val, buf)\
	if (attr == BTRFS_FS_DEV_ATTR_PTR(name))\
		return btrfs_show_d(val, buf)

static ssize_t btrfs_fs_devs_attr_show(struct kobject *kobj,
				       struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_devices *fs_devs = to_fs_devs(kobj);

	BTRFS_FS_DEVS_GET_ATTR_UUID(&a->attr, fsid, fs_devs->fsid, buf);
	BTRFS_FS_DEVS_GET_ATTR_U64(&a->attr, num_devices, &fs_devs->num_devices, buf);
	BTRFS_FS_DEVS_GET_ATTR_U64(&a->attr, open_devices, &fs_devs->open_devices, buf);
	BTRFS_FS_DEVS_GET_ATTR_U64(&a->attr, rw_devices, &fs_devs->rw_devices, buf);
	BTRFS_FS_DEVS_GET_ATTR_U64(&a->attr, missing_devices,
							&fs_devs->missing_devices, buf);
	BTRFS_FS_DEVS_GET_ATTR_U64(&a->attr, total_rw_bytes,
							&fs_devs->total_rw_bytes, buf);
	BTRFS_FS_DEVS_GET_ATTR_U64(&a->attr, total_devices, &fs_devs->total_devices, buf);
	BTRFS_FS_DEVS_GET_ATTR_D(&a->attr, opened, fs_devs->opened, buf);
	BTRFS_FS_DEVS_GET_ATTR_D(&a->attr, seeding, fs_devs->seeding, buf);
	BTRFS_FS_DEVS_GET_ATTR_D(&a->attr, rotating, fs_devs->rotating, buf);

	return 0;
}

static ssize_t btrfs_fs_devs_attr_store(struct kobject *kobj,
					struct kobj_attribute *a,
					const char *buf, size_t count)
{
	/*
	 * we might need some of the parameter to be writable
	 * but as of now just deny all
	 */
	return -EPERM;
}


static umode_t btrfs_sysfs_visible_fs_devs_attr(struct kobject *kobj,
				     struct attribute *attr, int unused)
{
	struct btrfs_fs_devices *fs_devs = to_fs_devs(kobj);
	struct btrfs_fs_info *fs_info = fs_devs->fs_info;

	/* if device is mounted then all is visible */
	if (fs_devs->opened && fs_info && !fs_info->closing)
		return attr->mode|S_IWUSR;

	/* when device is unmounted(ing) show only following set*/
	if (attr == BTRFS_FS_DEV_ATTR_PTR(num_devices))
		return attr->mode|S_IWUSR;
	else if (attr == BTRFS_FS_DEV_ATTR_PTR(total_devices))
		return attr->mode|S_IWUSR;
	else if (attr == BTRFS_FS_DEV_ATTR_PTR(opened))
		return attr->mode|S_IWUSR;
	else if (attr == BTRFS_FS_DEV_ATTR_PTR(fsid))
		return attr->mode|S_IWUSR;

	return 0;
}

static const struct attribute_group btrfs_fs_devs_attr_group = {
	.attrs = btrfs_fs_devs_attrs,
	.is_visible = btrfs_sysfs_visible_fs_devs_attr,
};

void btrfs_sysfs_rm_fsid_attr(struct btrfs_fs_devices *fs_devs)
{
	sysfs_remove_group(&fs_devs->fsid_kobj,
				&btrfs_fs_devs_attr_group);
}

int btrfs_sysfs_add_fsid_attr(struct btrfs_fs_devices *fs_devs)
{
	int rc;

	rc = sysfs_create_group(&fs_devs->fsid_kobj,
				&btrfs_fs_devs_attr_group);
	return rc;
}

static int btrfs_sysfs_update_fsid_attr(struct btrfs_fs_devices *fs_devs)
{
	int rc;

	rc = sysfs_update_group(&fs_devs->fsid_kobj,
				&btrfs_fs_devs_attr_group);

	return rc;
}

/**** btrfs_device kobject and attributes ****/
static ssize_t btrfs_dev_attr_show(struct kobject *kobj,
			       struct kobj_attribute *a, char *buf);
static ssize_t btrfs_dev_attr_store(struct kobject *kobj,
				struct kobj_attribute *a,
				const char *buf, size_t count);

struct btrfs_dev_attr {
	struct kobj_attribute kobj_attr;
};

static void btrfs_release_dev_kobj(struct kobject *kobj)
{
	struct btrfs_device *dev = to_btrfs_dev(kobj);

	kfree(dev->dev_kobjp);
	dev->dev_kobjp = NULL;
	complete(&dev->dev_kobj_unregister);
}

static struct kobj_type btrfs_dev_ktype = {
	.sysfs_ops	= &kobj_sysfs_ops,
	.release	= btrfs_release_dev_kobj,
};

static inline struct btrfs_device *to_btrfs_dev(struct kobject *kobj)
{
	struct btrfs_device_kobj *dev_kobj;

	if (kobj->ktype != &btrfs_dev_ktype)
		return NULL;

	dev_kobj = container_of(kobj, struct btrfs_device_kobj, dev_kobj);
	return dev_kobj->device;
}


#define BTRFS_DEV_ATTR(_name)\
	static struct btrfs_dev_attr btrfs_dev_attr_##_name = {\
		.kobj_attr = __INIT_KOBJ_ATTR(_name, S_IRUGO,\
					btrfs_dev_attr_show,\
					btrfs_dev_attr_store),\
	}

BTRFS_DEV_ATTR(uuid);
BTRFS_DEV_ATTR(name);
BTRFS_DEV_ATTR(devid);
BTRFS_DEV_ATTR(dev_root_fsid);
BTRFS_DEV_ATTR(generation);
BTRFS_DEV_ATTR(total_bytes);
BTRFS_DEV_ATTR(dev_totalbytes);
BTRFS_DEV_ATTR(bytes_used);
BTRFS_DEV_ATTR(type);
BTRFS_DEV_ATTR(io_align);
BTRFS_DEV_ATTR(io_width);
BTRFS_DEV_ATTR(sector_size);
BTRFS_DEV_ATTR(writeable);
BTRFS_DEV_ATTR(in_fs_metadata);
BTRFS_DEV_ATTR(missing);
BTRFS_DEV_ATTR(can_discard);
BTRFS_DEV_ATTR(replace_tgtdev);
BTRFS_DEV_ATTR(active_pending);
BTRFS_DEV_ATTR(nobarriers);
BTRFS_DEV_ATTR(devstats_valid);
BTRFS_DEV_ATTR(bdev);

#define BTRFS_DEV_ATTR_PTR(_name)\
		(&btrfs_dev_attr_##_name.kobj_attr.attr)

static struct attribute *btrfs_dev_attrs[] = {
	BTRFS_DEV_ATTR_PTR(uuid),
	BTRFS_DEV_ATTR_PTR(name),
	BTRFS_DEV_ATTR_PTR(devid),
	BTRFS_DEV_ATTR_PTR(dev_root_fsid),
	BTRFS_DEV_ATTR_PTR(generation),
	BTRFS_DEV_ATTR_PTR(total_bytes),
	BTRFS_DEV_ATTR_PTR(dev_totalbytes),
	BTRFS_DEV_ATTR_PTR(bytes_used),
	BTRFS_DEV_ATTR_PTR(type),
	BTRFS_DEV_ATTR_PTR(io_align),
	BTRFS_DEV_ATTR_PTR(io_width),
	BTRFS_DEV_ATTR_PTR(sector_size),
	BTRFS_DEV_ATTR_PTR(writeable),
	BTRFS_DEV_ATTR_PTR(in_fs_metadata),
	BTRFS_DEV_ATTR_PTR(missing),
	BTRFS_DEV_ATTR_PTR(can_discard),
	BTRFS_DEV_ATTR_PTR(replace_tgtdev),
	BTRFS_DEV_ATTR_PTR(active_pending),
	BTRFS_DEV_ATTR_PTR(nobarriers),
	BTRFS_DEV_ATTR_PTR(devstats_valid),
	BTRFS_DEV_ATTR_PTR(bdev),
	NULL
};

#define BTRFS_DEV_GET_ATTR_UUID(attr, name, valprt, buf)\
	if (attr == BTRFS_DEV_ATTR_PTR(name))\
		return btrfs_show_uuid(valprt, buf)
#define BTRFS_DEV_GET_ATTR_STR(attr, name, strprt, buf)\
	if (attr == BTRFS_DEV_ATTR_PTR(name))\
		return btrfs_show_str(strprt, buf)
#define BTRFS_DEV_GET_ATTR_U64(attr, name, valprt, buf)\
	if (attr == BTRFS_DEV_ATTR_PTR(name))\
		return btrfs_show_u64(valprt, NULL, buf)
#define BTRFS_DEV_GET_ATTR_U(attr, name, val, buf)\
	if (attr == BTRFS_DEV_ATTR_PTR(name))\
		return btrfs_show_u(val, buf)
#define BTRFS_DEV_GET_ATTR_D(attr, name, val, buf)\
	if (attr == BTRFS_DEV_ATTR_PTR(name))\
		return btrfs_show_d(val, buf)
#define BTRFS_DEV_CHECK_ATTR(attr, name)\
		attr == BTRFS_DEV_ATTR_PTR(name)

static ssize_t btrfs_dev_attr_show(struct kobject *kobj,
				       struct kobj_attribute *a, char *buf)
{
	struct btrfs_device *dev = to_btrfs_dev(kobj);
	char bdev_state[10];

	/* Todo: handle the missing device case */
	BTRFS_DEV_GET_ATTR_STR(&a->attr, name, rcu_str_deref(dev->name), buf);
	BTRFS_DEV_GET_ATTR_UUID(&a->attr, uuid, dev->uuid, buf);
	BTRFS_DEV_GET_ATTR_U64(&a->attr, devid, &dev->devid, buf);
	BTRFS_DEV_GET_ATTR_UUID(&a->attr, dev_root_fsid,
					dev->dev_root->fs_info->fsid, buf);
	BTRFS_DEV_GET_ATTR_U64(&a->attr, generation, &dev->generation, buf);
	BTRFS_DEV_GET_ATTR_U64(&a->attr, total_bytes, &dev->total_bytes, buf);
	BTRFS_DEV_GET_ATTR_U64(&a->attr, dev_totalbytes, &dev->disk_total_bytes, buf);
	BTRFS_DEV_GET_ATTR_U64(&a->attr, bytes_used, &dev->bytes_used, buf);
	BTRFS_DEV_GET_ATTR_U64(&a->attr, type, &dev->type, buf);
	BTRFS_DEV_GET_ATTR_U(&a->attr, io_align, dev->io_align, buf);
	BTRFS_DEV_GET_ATTR_U(&a->attr, sector_size, dev->sector_size, buf);
	BTRFS_DEV_GET_ATTR_D(&a->attr, writeable, dev->writeable, buf);
	BTRFS_DEV_GET_ATTR_D(&a->attr, in_fs_metadata, dev->in_fs_metadata, buf);
	BTRFS_DEV_GET_ATTR_D(&a->attr, missing, dev->missing, buf);
	BTRFS_DEV_GET_ATTR_D(&a->attr, can_discard, dev->can_discard, buf);
	BTRFS_DEV_GET_ATTR_D(&a->attr, replace_tgtdev,
						dev->is_tgtdev_for_dev_replace, buf);
	BTRFS_DEV_GET_ATTR_D(&a->attr, active_pending, dev->running_pending, buf);
	BTRFS_DEV_GET_ATTR_D(&a->attr, nobarriers, dev->nobarriers, buf);
	BTRFS_DEV_GET_ATTR_D(&a->attr, devstats_valid, dev->dev_stats_valid, buf);
	if (dev->bdev)
		strcpy(bdev_state, "not_null");
	else
		strcpy(bdev_state, "null");
	BTRFS_DEV_GET_ATTR_STR(&a->attr, bdev, bdev_state, buf);

	return 0;
}

static ssize_t btrfs_dev_attr_store(struct kobject *kobj,
					struct kobj_attribute *a,
					const char *buf, size_t count)
{
	/*
	 * we might need some of the parameter to be writable
	 * but as of now just deny all
	 */
	return -EPERM;
}

static umode_t btrfs_sysfs_visible_dev_attr(struct kobject *kobj,
				     struct attribute *attr, int unused)
{
	struct btrfs_fs_devices *fs_devs;
	struct btrfs_fs_info *fs_info;

	fs_devs = to_btrfs_dev(kobj)->fs_devices;
	if (!fs_devs) {
		BUG_ON(fs_devs == NULL);
		return 0;
	}
	fs_info = fs_devs->fs_info;

	/* if device is mounted then all is visible */
	if (fs_devs->opened && fs_info && !fs_info->closing)
		return attr->mode|S_IWUSR;

	/* when device is unmounted  only the below attributes are visible */
	if (attr == BTRFS_DEV_ATTR_PTR(uuid))
		return attr->mode|S_IWUSR;
	if (attr == BTRFS_DEV_ATTR_PTR(name))
		return attr->mode|S_IWUSR;
	else if (attr == BTRFS_DEV_ATTR_PTR(devid))
		return attr->mode|S_IWUSR;
	else if (attr == BTRFS_DEV_ATTR_PTR(generation))
		return attr->mode|S_IWUSR;

	return 0;
}

static const struct attribute_group btrfs_dev_attr_group = {
	.attrs = btrfs_dev_attrs,
	.is_visible = btrfs_sysfs_visible_dev_attr,
};

void btrfs_sysfs_rm_device_attr(struct btrfs_device *dev)
{
	if (dev->dev_kobjp) {
		struct kobject *kobj = &dev->dev_kobjp->dev_kobj;

		if (kobj->state_initialized) {
			sysfs_remove_group(kobj, &btrfs_dev_attr_group);
			kobject_del(kobj);
			kobject_put(kobj);
			wait_for_completion(&dev->dev_kobj_unregister);
			return;
		}
	}
	pr_warn("Btrfs: sysfs: dev destroy called for non init kobj\n");
	return;
}

void btrfs_sysfs_rm_devices_attr(struct btrfs_fs_devices *fs_devs)
{
	struct btrfs_device *dev;

	list_for_each_entry(dev, &fs_devs->devices, dev_list) {
		btrfs_sysfs_rm_device_attr(dev);
	}
}

int btrfs_sysfs_add_device_attr(struct btrfs_device *dev)
{
	int rc;
	struct kobject *kobj;

	if (!dev->dev_kobjp)
		dev->dev_kobjp = kzalloc(sizeof(struct btrfs_device_kobj),
								GFP_NOFS);
	else
		return -EEXIST;

	if (!dev->dev_kobjp)
		return -ENOMEM;

	dev->dev_kobjp->device = dev;
	kobj = &dev->dev_kobjp->dev_kobj;

	init_completion(&dev->dev_kobj_unregister);

	rc = kobject_init_and_add(kobj, &btrfs_dev_ktype,
			dev->fs_devices->device_dir_kobj, "%pU", dev->uuid);
	if (!rc)
		rc = sysfs_create_group(kobj, &btrfs_dev_attr_group);

	return rc;
}

void btrfs_sysfs_add_devices_attr(struct btrfs_fs_devices *fs_devs)
{
	struct btrfs_device *dev;

	list_for_each_entry(dev, &fs_devs->devices, dev_list) {
		if (btrfs_sysfs_add_device_attr(dev))
			printk(KERN_WARNING "BTRFS: create dev sysfs failed\n");
	}
}

static int btrfs_sysfs_update_device_attr(struct btrfs_device *dev)
{
	struct kobject *kobj = &dev->dev_kobjp->dev_kobj;

	if (!kobj)
		return -EINVAL;

	return sysfs_update_group(kobj, &btrfs_dev_attr_group);
}

static int btrfs_sysfs_update_devices_attr(struct btrfs_fs_devices *fs_devs)
{
	int rc;
	struct btrfs_device *dev;

	list_for_each_entry(dev, &fs_devs->devices, dev_list) {
		if (!dev->dev_kobjp)
			continue;
		rc = btrfs_sysfs_update_device_attr(dev);
		if (rc) {
			pr_warn("BTRFS: update dev sysfs failed\n");
			return rc;
		}
	}
	return 0;
}

int btrfs_sysfs_update_fsid_devices_attr(struct btrfs_fs_devices *fs_devs,
							int follow_seed)
{
	int rc;

again_for_seeds:
	rc = btrfs_sysfs_update_fsid_attr(fs_devs);
	rc = btrfs_sysfs_update_devices_attr(fs_devs);

	if (follow_seed && fs_devs->seed) {
		fs_devs = fs_devs->seed;
		goto again_for_seeds;
	}

	return rc;
}
