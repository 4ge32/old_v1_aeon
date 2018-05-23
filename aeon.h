#include "aeon_def.h"

/*
 * Debug code
 */
#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

/* #define aeon_dbg(s, args...)         pr_debug(s, ## args) */
#define aeon_dbg(s, args ...)           pr_info(s, ## args)
#define aeon_dbg1(s, args ...)
#define aeon_warn(s, args ...)          pr_warning(s, ## args)
#define aeon_info(s, args ...)          pr_info(s, ## args)


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

struct free_list {
	spinlock_t s_lock;
	struct rb_root	block_free_tree;
	struct aeon_range_node *first_node;
	unsigned long	block_start;
	unsigned long	block_end;
	unsigned long	num_free_blocks;
	unsigned long	num_blocknode;

	int             index;

	/* Statistics */
	unsigned long	alloc_log_count;
	unsigned long	alloc_data_count;
	unsigned long	free_log_count;
	unsigned long	free_data_count;
	unsigned long	alloc_log_pages;
	unsigned long	alloc_data_pages;
	unsigned long	freed_log_pages;
	unsigned long	freed_data_pages;

	u64		padding[8];	/* Cache line break */
};

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
 * NOVA super-block data in memory
 */
struct aeon_sb_info {
	struct super_block *sb;
	struct aeon_super_block *aeon_sb;
	struct block_device *s_bdev;
	struct dax_device *s_dax_dev;

	/*
	 * base physical and virtual address of NOVA (which is also
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
	struct free_list shared_free_list;
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

static inline struct aeon_inode_info *AEON_I(struct inode *inode)
{
	return container_of(inode, struct aeon_inode_info, vfs_inode);
}

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

	//return block ? ((void *)ps + block) : NULL;
	return block ? ((void *)ps) : NULL;
}

static inline int aeon_get_reference(struct super_block *sb, u64 block,
		void *dram, void **nvmm, size_t size)
{
	int rc;

	*nvmm = aeon_get_block(sb, block);
	aeon_dbg("%s: nvmm 0x%lx", __func__, (unsigned long)*nvmm);
	aeon_dbg("%s: dram 0x%lx", __func__, (unsigned long)dram);
	rc = memcpy_mcsafe(dram, *nvmm, size);
	return rc;
}

/* balloc.c  */
enum node_type {
	NODE_BLOCK = 1,
	NODE_INODE,
	NODE_DIR,
};

int aeon_alloc_block_free_lists(struct super_block *);
void aeon_init_blockmap(struct super_block *, int);
static inline struct free_list *aeon_get_free_list(struct super_block *sb, int cpu)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return &sbi->free_lists[cpu];
}

/* super.h */
#define NOVA_ROOT_INO		(1)
#define NOVA_INODETABLE_INO	(2)	/* Fake inode associated with inode
					 * stroage.  We need this because our
					 * allocator requires inode to be
					 * associated with each allocation.
					 * The data actually lives in linked
					 * lists in INODE_TABLE0_START. */
#define AEON_BLOCKNODE_INO	(3)     /* Storage for allocator state */

#define AEON_NORMAL_INODE_START (5)

struct aeon_range_node *aeon_alloc_inode_node(struct super_block *);


/* inode.h */
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
