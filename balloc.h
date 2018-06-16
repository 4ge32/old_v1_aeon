#ifndef __BALLOC_H
#define __BALLOC_H

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

enum node_type {
	NODE_BLOCK = 1,
	NODE_INODE,
	NODE_DIR,
};

int aeon_alloc_block_free_lists(struct super_block *);
void aeon_init_blockmap(struct super_block *);
int aeon_insert_range_node(struct rb_root *, struct aeon_range_node *, enum node_type);
int aeon_find_range_node(struct rb_root *tree, unsigned long key,
	enum node_type type, struct aeon_range_node **ret_node);
static inline struct free_list *aeon_get_free_list(struct super_block *sb, int cpu)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return &sbi->free_lists[cpu];
}

#endif
