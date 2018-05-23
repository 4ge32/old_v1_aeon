#include <linux/fs.h>
#include "aeon.h"

int aeon_insert_range_node(struct rb_root *tree, struct aeon_range_node *new_node, enum node_type type)
{
	return 0;
}

inline int aeon_insert_inodetree(struct aeon_sb_info *sbi, struct aeon_range_node *new_node, int cpu)
{
	struct rb_root *tree;
	int ret;

	tree = &sbi->inode_maps[cpu].inode_inuse_tree;
	ret = aeon_insert_range_node(tree, new_node, NODE_INODE);

	return ret;
}

int aeon_init_inode_inuse_list(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_range_node *range_node;
	struct inode_map *inode_map;
	unsigned long range_high;
	int i;
	int ret;

	return 0;

	sbi->s_inodes_used_count = AEON_NORMAL_INODE_START;

	range_high = AEON_NORMAL_INODE_START / sbi->cpus;
	if (AEON_NORMAL_INODE_START % sbi->cpus)
		range_high++;

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		range_node = aeon_alloc_inode_node(sb);
		if (range_node == NULL)
			return -ENOMEM;

		range_node->range_low = 0;
		range_node->range_high = range_high;
		//ret = aeon_insert_inodetree(sbi, range_node, i);
	}

	return 0;
}

int aeon_init_inode_table(struct super_block *sb)
{
	return 0;
}

int aeon_get_inode_address(struct super_block *sb, u64 ino, int version, u64 *pi_addr,
			   int extenable, int extend_alternate)
{
	if (ino < AEON_NORMAL_INODE_START)
		*pi_addr = aeon_get_reserved_inode_addr(sb, ino);
	return 0;
}

void aeon_set_inode_flags(struct inode *inode, struct aeon_inode *pi, unsigned int flags)
{
	inode->i_flags |= S_DAX;
}

/* copy persistent state to struct inode */
static int aeon_read_inode(struct super_block *sb, struct inode *inode, u64 pi_addr)
{
	struct aeon_inode_info *ai = AEON_I(inode);
	struct aeon_inode *pi, fake_pi;
	struct aeon_inode_info_header *aih = &ai->header;
	int ret = -EIO;
	unsigned long ino;
	int i = 0;

	aeon_dbg("%s: %d\n", __func__, i++);
	aeon_dbg("%s: pi_addr 0x%llu, %d\n", __func__, pi_addr, i++);
	ret = aeon_get_reference(sb, pi_addr, &fake_pi, (void **)&pi, sizeof(struct aeon_inode));
	if (ret) {
		aeon_dbg("%s: read pi 6 0x%llx failed\n", __func__, pi_addr);
		goto bad_inode;
	}
	aeon_dbg("%s: %d\n", __func__, i++);

	inode->i_mode = aih->i_mode;
	i_uid_write(inode, le32_to_cpu(pi->i_uid));
	i_gid_write(inode, le32_to_cpu(pi->i_gid));
	inode->i_generation = le32_to_cpu(pi->i_generation);
	aeon_set_inode_flags(inode, pi, le32_to_cpu(pi->i_flags));
	ino = inode->i_ino;

	/*
	if (inode->i_mode == 0 || pi->deleted == 1) {
		ret = -ESTALE;
		goto bad_inode;
	}
	*/

	aeon_dbg("%s: %d\n", __func__, i++);
	inode->i_blocks = aih->i_blocks;
	//inode->i_mapping->a_ops = &aeon_aops_dax;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		//inode->i_op = &aeon_file_inode_operations;
		//if (inplace_data_updates && wprotect == 0)
		//	inode->i_fop = &aeon_dax_file_operations;
		//else
		//	inode->i_fop = &aeon_wrap_file_operations;
		break;
	case S_IFDIR:
		//inode->i_op = &aeon_dir_inode_operations;
		//inode->i_fop = &aeon_dir_operations;
		break;
	//case S_IFLNK:
	//	inode->i_op = &aeon_symlink_inode_operations;
	//	break;
	//default:
	//	inode->i_op = &aeon_special_inode_operations;
	//	init_special_inode(inode, inode->i_mode,
	//			   le32_to_cpu(pi->dev.rdev));
		break;
	}

	inode->i_size = le64_to_cpu(aih->i_size);
	inode->i_atime.tv_sec = (__s32)le32_to_cpu(pi->i_atime);
	inode->i_ctime.tv_sec = (__s32)le32_to_cpu(pi->i_ctime);
	inode->i_mtime.tv_sec = (__s32)le32_to_cpu(pi->i_mtime);
	inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec =
					 inode->i_ctime.tv_nsec = 0;
	set_nlink(inode, le16_to_cpu(pi->i_links_count));
	aeon_dbg("%s: LAST  %d\n", __func__, i++);
	return 0;

bad_inode:
	make_bad_inode(inode);
	return ret;
}

int aeon_rebuild_inode(struct super_block *sb, struct aeon_inode_info *si,
		       u64 ino, u64 pi_addr, int rebuild_dir)
{
	return 0;
}

struct inode *aeon_iget(struct super_block *sb, unsigned long ino)
{
	struct inode *inode;
	struct aeon_inode_info *ai;
	u64 pi_addr = 0;
	int err;

	inode = iget_locked(sb, ino);
	if (unlikely(!inode))
		return ERR_PTR(ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	ai = AEON_I(inode);

	aeon_dbg("%s: inode %lu address 0x%lx\n", __func__, ino, (unsigned long)inode);

	err = aeon_get_inode_address(sb, ino, 0, &pi_addr, 0, 0);
	if (err) {
		aeon_dbg("%s: get inode address failed %d\n", __func__, err);
		goto fail;
	}

	aeon_dbg("%s: nvmm 0x%llu\n", __func__, pi_addr);

	if (pi_addr == 0) {
		aeon_dbg("%s: failed to get pi_addr for inode %lu\n", __func__, ino);
		err = -EACCES;
		goto fail;
	}

	err = aeon_rebuild_inode(sb, ai, ino, pi_addr, 1);
	if (err) {
		aeon_dbg("%s: failed to rebuild inode %lu\n", __func__, ino);
		goto fail;
	}

	err = aeon_read_inode(sb, inode, pi_addr);
	if (unlikely(err)) {
		aeon_dbg("%s: failed to read inode %lu\n", __func__, ino);
		goto fail;
	}

	inode->i_ino = ino;
	inode->i_mode = 0755;
	inode->i_sb = sb;
	inode->i_mode = S_IFDIR | 0777;

	unlock_new_inode(inode);
	aeon_dbg("%s: FINISH", __func__);
	return inode;
fail:
	iget_failed(inode);
	return ERR_PTR(err);
}
