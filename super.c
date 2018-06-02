#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/dax.h>
#include <linux/pfn_t.h>
#include <linux/genhd.h>
#include <linux/dcache.h>

#include "aeon.h"

static struct kmem_cache *aeon_inode_cachep;
static struct kmem_cache *aeon_range_node_cachep;
int support_clwb = 1;

static struct inode *aeon_alloc_inode(struct super_block *sb)
{
	struct aeon_inode_info *ai;

	ai = kmem_cache_alloc(aeon_inode_cachep, GFP_NOFS);
	if (!ai)
		return NULL;

	ai->vfs_inode.i_version = 1;

	return &ai->vfs_inode;
}

static void aeon_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct aeon_inode_info *ai = AEON_I(inode);

	aeon_dbg("%s: ino %lu\n", __func__, inode->i_ino);
	kmem_cache_free(aeon_inode_cachep, ai);
}

static void aeon_destroy_inode(struct inode *inode)
{
	aeon_dbg("%s: %lu\n", __func__, inode->i_ino);
	call_rcu(&inode->i_rcu, aeon_i_callback);
}

int aeon_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	//Maybe here should be implemented with synchronous way.
	return 0;
}

/*
 * dirty_inode() is called from mark_inode_dirty_sync()
 */
void aeon_dirty_inode(struct inode *inode, int flags)
{
}

void aeon_evict_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *ai = AEON_I(inode);
	struct aeon_inode_info_header *sih = &ai->header;
	struct aeon_inode *pi = aeon_get_inode(sb, inode);

	if (!sih) {
		aeon_dbg("%s: ino %lu sih is NULL\n", __func__, inode->i_ino);
		goto out;
	}

	if (pi && pi->aeon_ino != inode->i_ino) {
		aeon_dbg("%s: inode %lu ino does not match %llu\n",
				__func__, inode->i_ino, pi->aeon_ino);
	}

out:
	aeon_dbg("%s: FAILED\n", __func__);
}

static struct super_operations aeon_sops = {
	.alloc_inode   = aeon_alloc_inode,
	.destroy_inode = aeon_destroy_inode,
	.write_inode   = aeon_write_inode,
	.dirty_inode   = aeon_dirty_inode,
	.evict_inode   = aeon_evict_inode,
};

struct aeon_range_node *aeon_alloc_range_node(struct super_block *sb)
{
	struct aeon_range_node *p;

	p = (struct aeon_range_node *)kmem_cache_zalloc(aeon_range_node_cachep, GFP_NOFS);

	return p;
}

struct aeon_range_node *aeon_alloc_inode_node(struct super_block *sb)
{
	return aeon_alloc_range_node(sb);
}


static void aeon_set_blocksize(struct super_block *sb, unsigned long size)
{
	int bits;

	bits = fls(size) - 1;
	sb->s_blocksize_bits = bits;
	sb->s_blocksize = (1 << bits);
}

static void init_once(void *foo)
{
	struct aeon_inode_info *vi = foo;
	inode_init_once(&vi->vfs_inode);
}

static int __init init_inodecache(void)
{
	aeon_inode_cachep = kmem_cache_create("aeon_inode_cache",
					       sizeof(struct aeon_inode_info),
					       0, (SLAB_RECLAIM_ACCOUNT |
						   SLAB_MEM_SPREAD), init_once);
	if (aeon_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before
	 * we destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(aeon_inode_cachep);
}

static int aeon_get_nvmm_info(struct super_block *sb,
	struct aeon_sb_info *sbi)
{
	void *virt_addr = NULL;
	pfn_t __pfn_t;
	long size;
	struct dax_device *dax_dev;
	int ret;


	ret = bdev_dax_supported(sb, PAGE_SIZE);
	aeon_dbg("%s: dax_supported = %d; bdev->super=0x%p",
		 __func__, ret, sb->s_bdev->bd_super);
	if (ret) {
		//aeon_dbg(sb, "device does not support DAX\n");
		return ret;
	}

	sbi->s_bdev = sb->s_bdev;

	dax_dev = fs_dax_get_by_host(sb->s_bdev->bd_disk->disk_name);
	if (!dax_dev) {
		//aeon_err(sb, "Couldn't retrieve DAX device.\n");
		return -EINVAL;
	}
	sbi->s_dax_dev = dax_dev;

	size = dax_direct_access(sbi->s_dax_dev, 0, LONG_MAX/PAGE_SIZE,
				 &virt_addr, &__pfn_t) * PAGE_SIZE;
	if (size <= 0) {
		//aeon_err(sb, "direct_access failed\n");
		return -EINVAL;
	}

	sbi->virt_addr = virt_addr;

	if (!sbi->virt_addr) {
		//aeon_err(sb, "ioremap of the aeon image failed(1)\n");
		return -EINVAL;
	}

	sbi->phys_addr = pfn_t_to_pfn(__pfn_t) << PAGE_SHIFT;
	sbi->initsize = size;

	aeon_dbg("%s: dev %s, phys_addr 0x%llx, virt_addr 0x%lx, size %ld\n",
		__func__, sbi->s_bdev->bd_disk->disk_name,
		sbi->phys_addr, (unsigned long)sbi->virt_addr, sbi->initsize);

	return 0;
}

//static void aeon_root_check(struct super_block *sb, struct aeon_inode *root_pi)
//{
//	if (!S_ISDIR(le16_to_cpu(root_pi->i_mode)))
//		aeon_dbg("root is not a directory\n");
//}

static struct aeon_inode *aeon_init(struct super_block *sb, unsigned long size)
{
	unsigned long blocksize;
	struct aeon_inode *root_i, *pi;
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_super_block *aeon_sb;
	int i = 0;

	sbi->num_blocks = ((unsigned long)(size) >> PAGE_SHIFT);

	aeon_dbg("%s: %d\n", __func__, i++);
	sbi->blocksize = blocksize = AEON_DEF_BLOCK_SIZE_4K;
	aeon_set_blocksize(sb, sbi->blocksize);

	aeon_dbg("%s: %d\n", __func__, i++);
	aeon_sb = aeon_get_super(sb);

	aeon_dbg("%s: %d\n", __func__, i++);
	pi = aeon_get_inode_by_ino(sb, AEON_BLOCKNODE_INO);
	aeon_dbg("%s: %d, addr 0x%lx\n", __func__, i++, (unsigned long)pi);
	pi->aeon_ino = AEON_BLOCKNODE_INO;
	aeon_dbg("%s: %d, addr 0x%lx, aeon_ino %llu\n", __func__, i++, (unsigned long)pi, pi->aeon_ino);
	//aeon_flush_buffer(pi, CACHELINE_SIZE, 1);

	aeon_dbg("%s: %d\n", __func__, i++);
	aeon_init_blockmap(sb, 0);

	aeon_dbg("%s: %d\n", __func__, i++);
	if (aeon_init_inode_inuse_list(sb) < 0) {
		aeon_dbg("%s: %s is failed\n", __func__, "aeon_init_inuse_list");
		return NULL;
	}

	aeon_dbg("%s: %d\n", __func__, i++);
	if (aeon_init_inode_table(sb) < 0) {
		aeon_dbg("%s: %s is failed\n", __func__, "aeon_init_inode_table");
		return NULL;
	}

	aeon_dbg("%s: %d\n", __func__, i++);
	sbi->aeon_sb->s_size = cpu_to_le64(size);

	aeon_dbg("%s: %d\n", __func__, i++);
	root_i = aeon_get_inode_by_ino(sb, AEON_ROOT_INO);

	return root_i;
}

static int aeon_fill_super(struct super_block *sb, void *data, int silent)
{
	//struct aeon_super_block *asb;
	struct aeon_inode *root_pi;
	struct aeon_sb_info *sbi;
	struct inode *root_i;
	struct inode_map *inode_map;
	//unsigned long blocksize;
	int ret = -EINVAL;
	int i;

	sbi = kzalloc(sizeof(struct aeon_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sbi->aeon_sb = kzalloc(sizeof(struct aeon_sb_info), GFP_KERNEL);
	if (!sbi->aeon_sb) {
		kfree(sbi);
		return -ENOMEM;
	}

	sb->s_fs_info = sbi;
	sb->s_op = &aeon_sops;

	sbi->cpus = num_online_cpus();
	sbi->map_id = 0;

	aeon_dbg("The number of cpus: %d\n", sbi->cpus);

	aeon_dbg("START: aeon_get_nvmm_info");
	ret = aeon_get_nvmm_info(sb, sbi);
	if (ret)
		goto out;
	aeon_dbg("FINISH: aeon_get_nvmm_info");

	sbi->mode = (0755);
	sbi->uid  = current_fsuid();
	sbi->gid  = current_fsgid();

	sbi->inode_maps = kcalloc(sbi->cpus, sizeof(struct inode_map), GFP_KERNEL);
	if(!sbi->inode_maps) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		mutex_init(&inode_map->inode_table_mutex);
		inode_map->inode_inuse_tree = RB_ROOT;
	}

	mutex_init(&sbi->s_lock);

	sbi->zeroed_page = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!sbi->zeroed_page) {
		ret = -ENOMEM;
		goto out1;
	}

	aeon_dbg("START: aeon_alloc_block_free_lists");
	if (aeon_alloc_block_free_lists(sb)) {
		ret = -ENOMEM;
		goto out2;
	}
	aeon_dbg("FINISH: aeon_alloc_block_free_lists");


	aeon_dbg("START: aeon_init");
	root_pi = aeon_init(sb, sbi->initsize);
	ret = -ENOMEM;
	if (IS_ERR(root_pi))
		goto out2;
	aeon_dbg("FINISH: aeon_init");

	aeon_dbg("START: aeon_iget");
	root_i = aeon_iget(sb, AEON_ROOT_INO);
	aeon_dbg("MIDDLE: aeon_iget");
	if (IS_ERR(root_i)) {
		ret = -ENOMEM;
		aeon_dbg("%s ERR root_i\n", __func__);
		goto out2;
	}
	aeon_dbg("FINISH: aeon_iget");
	aeon_dbg("%s: CONFIRM %lu\n", __func__, root_i->i_ino);

	aeon_dbg("START: d_make_root\n");
	sb->s_root = d_make_root(root_i);
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto out2;
	}
	aeon_dbg("FINISH: d_make_root\n");
		/*
	blocksize = le32_to_cpu(sbi->aeon_sb->s_blocksize);
	aeon_set_blocksize(sb, blocksize);

	root_pi = aeon_get_inode_by_ino(sb, AEON_ROOT_INO);

	aeon_root_check(sb, root_pi);
	*/

	return 0;

out2:
	aeon_dbg("%s: free zeroed_page\n", __func__);
	kfree(sbi->zeroed_page);
out1:
	aeon_dbg("%s: free inode_maps\n", __func__);
	kfree(sbi->inode_maps);
out:
	kfree(sbi);

	aeon_dbg("%s failed: return %d\n", __func__, ret);
	return ret;
}

static struct dentry *aeon_mount(struct file_system_type *fs_type,
				  int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, aeon_fill_super);
}

static struct file_system_type aeon_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "aeon",
	.mount		= aeon_mount,
	.kill_sb	= kill_block_super,
};


static int __init init_aeon_fs(void)
{
	int err;

	err = init_inodecache();
	if (err)
		goto out1;

	err = register_filesystem(&aeon_fs_type);
	if (err)
		goto out;

	return 0;
out:
	destroy_inodecache();
out1:
	return err;
}

static void __exit exit_aeon_fs(void)
{
	unregister_filesystem(&aeon_fs_type);
	//remove_proc_entry(proc_dirname, NULL);
	destroy_inodecache();
	//destroy_rangenode_cache();
}

MODULE_AUTHOR("Fumiya Shigemitsu");
MODULE_DESCRIPTION("AEON: A Persistent Memory File System");
MODULE_LICENSE("GPL");

module_init(init_aeon_fs)
module_exit(exit_aeon_fs)
