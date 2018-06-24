#ifndef __AEON_H
#define __AEON_H

#include "aeon_def.h"
#include <linux/uaccess.h>

/*
 * Debug code
 */
#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

/* #define aeon_dbg(s, args...)         pr_debug(s, ## args) */
extern void aeon_err_msg(struct super_block *, const char *, ...);
#define aeon_dbg(s, args ...)           pr_info(s, ## args)
#define aeon_dbg1(s, args ...)
#define aeon_err(sb, s, args ...)       aeon_err_msg(sb, s, ## args)
#define aeon_warn(s, args ...)          pr_warning(s, ## args)
#define aeon_info(s, args ...)          pr_info(s, ## args)

#define set_opt(o, opt)		(o |= AEON_MOUNT_ ## opt)

#define	READDIR_END		(ULONG_MAX)
#define	ANY_CPU			(65536)

extern int wprotect;

struct aeon_file_write_entry {
	/* ret of find_nvmm_block, the lowest byte is entry type */
	__le64	block;
	__le64	pgoff;
	__le32	num_pages;
	__le32	invalid_pages;
	/* For both ctime and mtime */
	__le32	mtime;
	__le32	padding;
	__le64	size;
} __attribute((__packed__));

/*
 * The first block contains super blocks and reserved inodes;
 * The second block contains pointers to inode tables.
 */
#define	RESERVED_BLOCKS	2

struct inode_map {
	struct mutex inode_table_mutex;
	struct rb_root	inode_inuse_tree;
	unsigned long	num_range_node_inode;
	struct aeon_range_node *first_inode_range;
	int allocated;
	int freed;
};

/*
 * AEON super-block data in memory
 */
struct aeon_sb_info {
	struct super_block *sb;
	struct aeon_super_block *aeon_sb; struct block_device *s_bdev;
	struct dax_device *s_dax_dev;

	/*
	 * base physical and virtual address of AEON (which is also
	 * the pointer to the super block)
	 */
	phys_addr_t	phys_addr;
	void		*virt_addr;

	unsigned long	num_blocks;

	/*
	 * Backing store option:
	 * 1 = no load, 2 = no store,
	 * else do both
	 */
	unsigned int	aeon_backing_option;

	/* Mount options */
	unsigned long	bpi;
	unsigned long	num_inodes;
	unsigned long	blocksize;
	unsigned long	initsize;
	unsigned long	s_mount_opt;
	kuid_t		uid;    /* Mount uid for root directory */
	kgid_t		gid;    /* Mount gid for root directory */
	umode_t		mode;   /* Mount mode for root directory */
	atomic_t	next_generation;
	/* inode tracking */
	unsigned long	s_inodes_used_count;
	unsigned long	reserved_blocks;

	struct mutex 	s_lock;	/* protects the SB's buffer-head */

	int cpus;
	struct proc_dir_entry *s_proc;

	/* ZEROED page for cache page initialized */
	void *zeroed_page;

	/* Per-CPU journal lock */
	spinlock_t *journal_locks;

	/* Per-CPU inode map */
	struct inode_map	*inode_maps;

	/* Decide new inode map id */
	unsigned long map_id;

	/* Per-CPU free block list */
	struct free_list *free_lists;

	/* Shared free block list */
	unsigned long per_list_blocks;
	//struct free_list shared_free_list;
};

struct aeon_range_node {
	struct rb_node node;
	struct vm_area_struct *vma;
	unsigned long mmap_entry;
	union {
		struct {
			unsigned long range_low;
			unsigned long range_high;
		};
		struct {
			unsigned long hash;
			void *direntry;
		};
	};
	u32 csum;
};

static inline struct aeon_sb_info *AEON_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}


/*
 * Get the persistent memory's address
 */
static inline struct aeon_super_block *aeon_get_super(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return (struct aeon_super_block *)sbi->virt_addr;
}

/* Translate an offset the beginning of the aeon instance to a PMEM address.
 *
 * If this is part of a read-modify-write of the block,
 * aeon_memunlock_block() before calling!
 */
static inline void *aeon_get_block(struct super_block *sb, u64 block)
{
	struct aeon_super_block *ps = aeon_get_super(sb);

	aeon_dbg("%s : virt_addr + 0x%llx\n", __func__, block);

	//return block ? ((void *)ps + block) : NULL;
	return block ? ((void *)ps + block) : NULL;
}

static inline int aeon_get_reference(struct super_block *sb, u64 block,
		void *dram, void **nvmm, size_t size)
{
	int rc = 0;

	*nvmm = aeon_get_block(sb, block);
	aeon_dbg("%s: nvmm 0x%lx", __func__, (unsigned long)*nvmm);
	//aeon_dbg("%s: dram 0x%lx", __func__, (unsigned long)dram);
	//rc = memcpy_mcsafe(dram, *nvmm, size);
	return rc;
}

static inline int memcpy_to_pmem_nocache(void *dst, const void *src, unsigned int size)
{
	int ret;

	ret = __copy_from_user_inatomic_nocache(dst, src, size);

	return ret;
}


/* super.h */
#define AEON_ROOT_INO		(1)
#define AEON_INODETABLE_INO	(2)	/* Fake inode associated with inode
					 * stroage.  We need this because our
					 * allocator requires inode to be
					 * associated with each allocation.
					 * The data actually lives in linked
					 * lists in INODE_TABLE0_START. */
#define AEON_BLOCKNODE_INO	(3)     /* Storage for allocator state */

#define AEON_NORMAL_INODE_START (5)

struct aeon_range_node *aeon_alloc_inode_node(struct super_block *);
void aeon_free_inode_node(struct aeon_range_node *);
struct aeon_range_node *aeon_alloc_range_node(struct super_block *sb);
void aeon_free_range_node(struct aeon_range_node *node);
void aeon_free_dir_node(struct aeon_range_node *node);

static inline int aeon_get_cpuid(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return smp_processor_id() % sbi->cpus;
}

// BKDR String Hash Function
static inline unsigned long BKDRHash(const char *str, int length)
{
	unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
	unsigned long hash = 0;
	int i;

	for (i = 0; i < length; i++)
		hash = hash * seed + (*str++);

	return hash;
}

static inline u64
aeon_get_block_off(struct super_block *sb, unsigned long blocknr,
		    unsigned short btype)
{
	return (u64)blocknr << PAGE_SHIFT;
}

extern const struct file_operations aeon_dax_file_operations;
extern const struct file_operations aeon_dir_operations;
extern const struct iomap_ops aeon_iomap_ops;
int aeon_add_dentry(struct dentry *dentry, u64 ino, int inc_link);
int aeon_remove_dentry(struct dentry *dentry, int dec_link, struct aeon_inode *update);


#endif
