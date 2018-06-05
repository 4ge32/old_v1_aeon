#ifndef __INODE_H_
#define __INODE_H_

//#include "aeon.h"

/* inode.h */
struct aeon_inode_info_header {
	/* Map from file offsets to write log entries. */
	struct radix_tree_root tree;
	struct rb_root rb_tree;		/* RB tree for directory */
	struct rb_root vma_tree;	/* Write vmas */
	struct list_head list;		/* SB list of mmap sih */
	int num_vmas;
	unsigned short i_mode;		/* Dir or file? */
	unsigned int i_flags;
	unsigned long log_pages;	/* Num of log pages */
	unsigned long i_size;
	unsigned long i_blocks;
	unsigned long ino;
	unsigned long pi_addr;
	unsigned long alter_pi_addr;
	unsigned long valid_entries;	/* For thorough GC */
	unsigned long num_entries;	/* For thorough GC */
	u64 last_setattr;		/* Last setattr entry */
	u64 last_link_change;		/* Last link change entry */
	u64 last_dentry;		/* Last updated dentry */
	u64 trans_id;			/* Transaction ID */
	u64 log_head;			/* Log head pointer */
	u64 log_tail;			/* Log tail pointer */
	u64 alter_log_head;		/* Alternate log head pointer */
	u64 alter_log_tail;		/* Alternate log tail pointer */
	u8  i_blk_type;
};

struct aeon_inode_info {
	struct aeon_inode_info_header header;
	struct inode vfs_inode;
};

static inline struct aeon_inode_info *AEON_I(struct inode *inode)
{
	return container_of(inode, struct aeon_inode_info, vfs_inode);
}


static inline struct aeon_inode *aeon_get_inode(struct super_block *sb,
	struct inode *inode)
{
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode fake_pi;
	void *addr;
	int rc;

	addr = aeon_get_block(sb, sih->pi_addr);
	rc = memcpy_mcsafe(&fake_pi, addr, sizeof(struct aeon_inode));
	if (rc)
		return NULL;

	return (struct aeon_inode *)addr;
}

static inline u64 aeon_get_addr_off(struct aeon_sb_info *sbi) {
	return (u64)sbi->virt_addr;
}

static inline u64 aeon_get_reserved_inode_addr(struct super_block *sb, u64 inode_number) {
	struct aeon_sb_info *sbi = AEON_SB(sb);

	aeon_dbg("%s : 0x%lx\n", __func__, (unsigned long)aeon_get_addr_off(sbi));
	return aeon_get_addr_off(sbi) + inode_number * AEON_INODE_SIZE;
}

static inline struct aeon_inode *aeon_get_reserved_inode(struct super_block *sb, u64 inode_number)
{
	//struct aeon_sb_info *sbi = AEON_SB(sb);
	u64 addr;

	addr = aeon_get_reserved_inode_addr(sb, inode_number);
	aeon_dbg("%s : 0x%lx\n", __func__, (unsigned long)addr);

	return (struct aeon_inode *)addr;
}

static inline struct aeon_inode *aeon_get_inode_by_ino(struct super_block *sb, u64 ino)
{
	if (ino == 0)
		return NULL;
	return aeon_get_reserved_inode(sb, ino);
}

int aeon_init_inode_inuse_list(struct super_block *);
int aeon_init_inode_table(struct super_block *);
struct inode *aeon_iget(struct super_block *, unsigned long);

#endif
