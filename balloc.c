#include <linux/slab.h>
#include <linux/fs.h>

#include "aeon.h"
#include "balloc.h"
#include "inode.h"
#include "mprotect.h"

int aeon_alloc_block_free_lists(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct free_list *free_list;
	int i;

	sbi->free_lists = kcalloc(sbi->cpus, sizeof(free_list), GFP_KERNEL);

	if(!sbi->free_lists)
		return -ENOMEM;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = aeon_get_free_list(sb, i);
		free_list->block_free_tree = RB_ROOT;
		spin_lock_init(&free_list->s_lock);
		free_list->index = i;
	}

	return 0;
}

static void aeon_init_free_list(struct super_block *sb, struct free_list *free_list, int index)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long per_list_blocks;

	per_list_blocks = sbi->num_blocks / sbi->cpus;

	free_list->block_start = per_list_blocks * index;
	free_list->block_end = free_list->block_start + per_list_blocks - 1;
}

void aeon_init_blockmap(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct rb_root *tree;
	struct free_list *free_list;
	int i;

	sbi->per_list_blocks = sbi->num_blocks / sbi->cpus;
	for (i = 0; i < sbi->cpus; i++) {
		free_list = aeon_get_free_list(sb, i);
		tree = &(free_list->block_free_tree);
		aeon_init_free_list(sb, free_list, i);
	}
}

static inline int aeon_rbtree_compare_rangenode(struct aeon_range_node *curr, unsigned long key, enum node_type type)
{
	if (type == NODE_DIR) {
		if (key < curr->hash)
			return -1;
		if (key > curr->hash)
			return 1;
		return 0;
	}

	/* Block and inode */
	if (key < curr->range_low)
		return -1;
	if (key > curr->range_high)
		return 1;

	return 0;
}

int aeon_find_range_node(struct rb_root *tree, unsigned long key,
	enum node_type type, struct aeon_range_node **ret_node)
{
	struct aeon_range_node *curr = NULL;
	struct rb_node *temp;
	int compVal;
	int ret = 0;

	temp = tree->rb_node;

	while (temp) {
		curr = container_of(temp, struct aeon_range_node, node);
		compVal = aeon_rbtree_compare_rangenode(curr, key, type);

		if (compVal == -1) {
			temp = temp->rb_left;
		} else if (compVal == 1) {
			temp = temp->rb_right;
		} else {
			ret = 1;
			break;
		}
	}

	*ret_node = curr;
	return ret;
}

int aeon_insert_range_node(struct rb_root *tree, struct aeon_range_node *new_node, enum node_type type)
{
	struct aeon_range_node *curr;
	struct rb_node **temp, *parent;
	int compVal;

	aeon_dbg("%s: START\n", __func__);

	temp = &(tree->rb_node);
	parent = NULL;

	while (*temp) {
		aeon_dbg("%s: MIDDLE\n", __func__);

		curr = container_of(*temp, struct aeon_range_node, node);
		compVal = aeon_rbtree_compare_rangenode(curr, new_node->range_low, type);

		parent = *temp;

		if (compVal == -1)
			temp = &((*temp)->rb_left);
		else if (compVal == 1)
			temp = &((*temp)->rb_right);
		else {
			aeon_dbg("%s: type %d entry %lu - %lu already exists: "
				"%lu - %lu\n",
				 __func__, type, new_node->range_low,
				new_node->range_high, curr->range_low,
				curr->range_high);
			return -EINVAL;
		}

	}

	rb_link_node(&new_node->node, parent, temp);
	rb_insert_color(&new_node->node, tree);

	aeon_dbg("%s: FINISH\n", __func__);
	return 0;
}

/* Used for both block free tree and inode inuse tree */
int aeon_find_free_slot(struct rb_root *tree, unsigned long range_low,
	unsigned long range_high, struct aeon_range_node **prev,
	struct aeon_range_node **next)
{
	struct aeon_range_node *ret_node = NULL;
	struct rb_node *tmp;
	int check_prev = 0, check_next = 0;
	int ret;

	ret = aeon_find_range_node(tree, range_low, NODE_BLOCK, &ret_node);
	if (ret) {
		aeon_dbg("%s ERROR: %lu - %lu already in free list\n",
			__func__, range_low, range_high);
		return -EINVAL;
	}

	if (!ret_node) {
		*prev = *next = NULL;
	} else if (ret_node->range_high < range_low) {
		*prev = ret_node;
		tmp = rb_next(&ret_node->node);
		if (tmp) {
			*next = container_of(tmp, struct aeon_range_node, node);
			check_next = 1;
		} else {
			*next = NULL;
		}
	} else if (ret_node->range_low > range_high) {
		*next = ret_node;
		tmp = rb_prev(&ret_node->node);
		if (tmp) {
			*prev = container_of(tmp, struct aeon_range_node, node);
			check_prev = 1;
		} else {
			*prev = NULL;
		}
	} else {
		aeon_dbg("%s ERROR: %lu - %lu overlaps with existing node %lu - %lu\n",
			 __func__, range_low, range_high, ret_node->range_low,
			ret_node->range_high);
		return -EINVAL;
	}

	return 0;
}

int aeon_insert_blocktree(struct rb_root *tree, struct aeon_range_node *new_node)
{
	int ret;

	ret = aeon_insert_range_node(tree, new_node, NODE_BLOCK);
	if (ret)
		aeon_dbg("ERROR: %s failed %d\n", __func__, ret);

	return ret;
}

struct aeon_range_node *aeon_alloc_blocknode(struct super_block *sb)
{
	return aeon_alloc_range_node(sb);
}

void aeon_free_blocknode(struct aeon_range_node *node)
{
	aeon_free_range_node(node);
}

static inline unsigned long aeon_get_numblocks(unsigned short btype)
{
	return 1;
}

static int aeon_free_blocks(struct super_block *sb, unsigned long blocknr,
	int num, unsigned short btype)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct rb_root *tree;
	unsigned long block_low;
	unsigned long block_high;
	unsigned long num_blocks = 0;
	struct aeon_range_node *prev = NULL;
	struct aeon_range_node *next = NULL;
	struct aeon_range_node *curr_node;
	struct free_list *free_list;
	int cpuid;
	int new_node_used = 0;
	int ret;

	if (num <= 0) {
		aeon_dbg("%s ERROR: free %d\n", __func__, num);
		return -EINVAL;
	}

	cpuid = blocknr / sbi->per_list_blocks;

	/* Pre-allocate blocknode */
	curr_node = aeon_alloc_blocknode(sb);
	if (curr_node == NULL) {
		/* returning without freeing the block*/
		return -ENOMEM;
	}

	free_list = aeon_get_free_list(sb, cpuid);
	spin_lock(&free_list->s_lock);

	tree = &(free_list->block_free_tree);

	num_blocks = aeon_get_numblocks(btype) * num;
	block_low = blocknr;
	block_high = blocknr + num_blocks - 1;

	aeon_dbg("Free: %lu - %lu\n", block_low, block_high);

	if (blocknr < free_list->block_start ||
			blocknr + num > free_list->block_end + 1) {
		aeon_err(sb, "free blocks %lu to %lu, free list %d, start %lu, end %lu\n",
				blocknr, blocknr + num - 1,
				free_list->index,
				free_list->block_start,
				free_list->block_end);
		ret = -EIO;
		goto out;
	}

	ret = aeon_find_free_slot(tree, block_low,
					block_high, &prev, &next);

	if (ret) {
		aeon_dbg("%s: find free slot fail: %d\n", __func__, ret);
		goto out;
	}

	if (prev && next && (block_low == prev->range_high + 1) &&
			(block_high + 1 == next->range_low)) {
		/* fits the hole */
		rb_erase(&next->node, tree);
		free_list->num_blocknode--;
		prev->range_high = next->range_high;
		if (free_list->last_node == next)
			free_list->last_node = prev;
		aeon_free_blocknode(next);
		goto block_found;
	}
	if (prev && (block_low == prev->range_high + 1)) {
		/* Aligns left */
		prev->range_high += num_blocks;
		goto block_found;
	}
	if (next && (block_high + 1 == next->range_low)) {
		/* Aligns right */
		next->range_low -= num_blocks;
		goto block_found;
	}

	/* Aligns somewhere in the middle */
	curr_node->range_low = block_low;
	curr_node->range_high = block_high;
	new_node_used = 1;
	ret = aeon_insert_blocktree(tree, curr_node);
	if (ret) {
		new_node_used = 0;
		goto out;
	}
	if (!prev)
		free_list->first_node = curr_node;
	if (!next)
		free_list->last_node = curr_node;

	free_list->num_blocknode++;

block_found:
	free_list->num_free_blocks += num_blocks;
	free_list->free_data_count++;
	free_list->freed_data_pages += num_blocks;

out:
	spin_unlock(&free_list->s_lock);
	if (new_node_used == 0)
		aeon_free_blocknode(curr_node);

	return ret;
}

int aeon_free_data_blocks(struct super_block *sb,
	struct aeon_inode_info_header *sih, unsigned long blocknr, int num)
{
	int ret;

	aeon_dbg("Inode %lu: free %d data block from %lu to %lu\n",
			sih->ino, num, blocknr, blocknr + num - 1);
	if (blocknr == 0) {
		aeon_dbg("%s: ERROR: %lu, %d\n", __func__, blocknr, num);
		return -EINVAL;
	}

	ret = aeon_free_blocks(sb, blocknr, num, sih->i_blk_type);
	if (ret) {
		aeon_err(sb, "Inode %lu: free %d data block from %lu to %lu failed!\n",
			 sih->ino, num, blocknr, blocknr + num - 1);
	}

	return ret;
}

/* Return how many blocks allocated */
static long aeon_alloc_blocks_in_free_list(struct super_block *sb,
	struct free_list *free_list, unsigned short btype,
	unsigned long num_blocks,
	unsigned long *new_blocknr)
{
	struct rb_root *tree;
	struct aeon_range_node *curr, *next = NULL, *prev = NULL;
	struct rb_node *temp, *next_node, *prev_node;
	unsigned long curr_blocks;
	bool found = 0;
	unsigned long step = 0;

	if (!free_list->first_node || free_list->num_free_blocks == 0) {
		aeon_dbg("%s: Can't alloc. free_list->first_node=0x%p free_list->num_free_blocks = %lu",
			  __func__, free_list->first_node,
			  free_list->num_free_blocks);
		return -ENOSPC;
	}

	tree = &(free_list->block_free_tree);
	temp = &(free_list->last_node->node);

	while (temp) {
		step++;
		curr = container_of(temp, struct aeon_range_node, node);

		curr_blocks = curr->range_high - curr->range_low + 1;

		if (num_blocks >= curr_blocks) {
			/* Superpage allocation must succeed */
			if (btype > 0 && num_blocks > curr_blocks)
				goto next;

			/* Otherwise, allocate the whole blocknode */
			if (curr == free_list->first_node) {
				next_node = rb_next(temp);
				if (next_node)
					next = container_of(next_node,
						struct aeon_range_node, node);
				free_list->first_node = next;
			}

			if (curr == free_list->last_node) {
				prev_node = rb_prev(temp);
				if (prev_node)
					prev = container_of(prev_node,
						struct aeon_range_node, node);
				free_list->last_node = prev;
			}

			rb_erase(&curr->node, tree);
			free_list->num_blocknode--;
			num_blocks = curr_blocks;
			*new_blocknr = curr->range_low;
			aeon_free_blocknode(curr);
			found = 1;
			break;
		}

		*new_blocknr = curr->range_high + 1 - num_blocks;
		curr->range_high -= num_blocks;

		found = 1;
		break;
next:
		temp = rb_prev(temp);
	}

	if (free_list->num_free_blocks < num_blocks) {
		aeon_dbg("%s: free list %d has %lu free blocks, but allocated %lu blocks?\n",
				__func__, free_list->index,
				free_list->num_free_blocks, num_blocks);
		return -ENOSPC;
	}

	if (found == 1)
		free_list->num_free_blocks -= num_blocks;
	else {
		aeon_dbg("%s: Can't alloc.  found = %d", __func__, found);
		return -ENOSPC;
	}

	return num_blocks;
}

/* Find out the free list with most free blocks */
static int aeon_get_candidate_free_list(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct free_list *free_list;
	int cpuid = 0;
	int num_free_blocks = 0;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = aeon_get_free_list(sb, i);
		if (free_list->num_free_blocks > num_free_blocks) {
			cpuid = i;
			num_free_blocks = free_list->num_free_blocks;
		}
	}

	return cpuid;
}

static int not_enough_blocks(struct free_list *free_list, unsigned long num_blocks)
{
	struct aeon_range_node *first = free_list->first_node;
	struct aeon_range_node *last = free_list->last_node;

	if (free_list->num_free_blocks < num_blocks || !first || !last) {
		aeon_dbg("%s: num_free_blocks=%ld; num_blocks=%ld; first=0x%p; last=0x%p",
			  __func__, free_list->num_free_blocks, num_blocks,
			  first, last);
		return 1;
	}

	return 0;
}

static int aeon_new_blocks(struct super_block *sb, unsigned long *blocknr, unsigned int num,
			   unsigned short btype, int cpuid)
{
	struct free_list *free_list;
	void *bp;
	unsigned long num_blocks = 0;
	unsigned long new_blocknr = 0;
	long ret_blocks = 0;
	int retried = 0;

	num_blocks = num * aeon_get_numblocks(btype);
	if (num_blocks == 0) {
		aeon_dbg("%s: num_blocks == 0", __func__);
		return -EINVAL;
	}

	if (cpuid == ANY_CPU)
		cpuid = aeon_get_cpuid(sb);

retry:
	free_list = aeon_get_free_list(sb, cpuid);
	spin_lock(&free_list->s_lock);

	if (not_enough_blocks(free_list, num_blocks)) {
		aeon_dbg("%s: cpu %d, free_blocks %lu, required %lu, blocknode %lu\n",
			  __func__, cpuid, free_list->num_free_blocks,
			  num_blocks, free_list->num_blocknode);

		if (retried >= 2)
			/* Allocate anyway */
			goto alloc;

		spin_unlock(&free_list->s_lock);
		cpuid = aeon_get_candidate_free_list(sb);
		retried++;
		goto retry;
	}
alloc:
	ret_blocks = aeon_alloc_blocks_in_free_list(sb, free_list, btype, num_blocks, &new_blocknr);

	if (ret_blocks > 0) {
		free_list->alloc_data_count++;
		free_list->alloc_data_pages += ret_blocks;
	}

	spin_unlock(&free_list->s_lock);

	if (ret_blocks <= 0 || new_blocknr == 0) {
		aeon_dbg("%s: not able to allocate %d blocks.  ret_blocks=%ld; new_blocknr=%lu",
				 __func__, num, ret_blocks, new_blocknr);
		return -ENOSPC;
	}

	bp = aeon_get_block(sb, aeon_get_block_off(sb,
					new_blocknr, btype));
	aeon_memunlock_range(sb, bp, PAGE_SIZE * ret_blocks);
	memset(bp, 0, PAGE_SIZE * ret_blocks);
	aeon_memlock_range(sb, bp, PAGE_SIZE * ret_blocks);
	*blocknr = new_blocknr;

	aeon_dbg("Alloc %lu NVMM blocks 0x%lx\n", ret_blocks, *blocknr);
	return ret_blocks / aeon_get_numblocks(btype);
}

int aeon_new_data_blocks(struct super_block *sb, struct aeon_inode_info_header *sih,
			 unsigned long *blocknr, unsigned long start_blk, unsigned int num, int cpu)
{
	int allocated;

	sih->i_blk_type = 0;
	allocated = aeon_new_blocks(sb, blocknr, num, sih->i_blk_type, cpu);
	if (allocated < 0) {
		aeon_dbg("FAILED: Inode %lu, start blk %lu, alloc %d data blocks from 0x%lx to 0x%lx\n",
			  sih->ino, start_blk, allocated, *blocknr,
			  *blocknr + allocated - 1);
	} else {
		aeon_dbg("Inode %lu, start blk %lu, alloc %d data blocks from %lu to %lu\n",
			  sih->ino, start_blk, allocated, *blocknr,
			  *blocknr + allocated - 1);
	}
	return allocated;
}

