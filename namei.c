#include <linux/fs.h>
#include <linux/pagemap.h>

#include "aeon.h"
#include "inode.h"
#include "balloc.h"


static int aeon_create(struct inode *dir, struct dentry *dentry, umode_t mode,
			bool excl)
{
	struct aeon_inode *pidir;
	struct super_block *sb = dir->i_sb;
	struct inode *inode = NULL;
	u64 pi_addr = 0;
	u64 ino;
	int err = PTR_ERR(inode);

	aeon_dbg("%s: START\n", __func__);
	pidir = aeon_get_inode(sb, dir);
	ino = aeon_new_aeon_inode(sb, &pi_addr);
	if (ino == 0)
		goto out;

	err = aeon_add_dentry(dentry, ino, 0);
	if (err)
		goto out;

	inode = aeon_new_vfs_inode(TYPE_CREATE, dir, pi_addr, ino, mode, 0, 0, &dentry->d_name);
	if (IS_ERR(inode))
		goto out;

	d_instantiate(dentry, inode);
	//unlock_new_inode(inode);

	aeon_dbg("%s: 0x%llx", __func__, pi_addr);

	aeon_dbg("%s: FINISH\n", __func__);
	return 0;
out:
	aeon_err(sb, "%s return %d\n", __func__, err);
	return err;
}

struct aeon_dentry *aeon_find_dentry(struct super_block *sb,
	struct aeon_inode *pi, struct inode *inode, const char *name,
	unsigned long name_len)
{
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_dentry *direntry = NULL;
	struct aeon_range_node *ret_node = NULL;
	unsigned long hash;
	int found = 0;

	hash = BKDRHash(name, name_len);

	aeon_dbg("%s", __func__);
	found = aeon_find_range_node(&sih->rb_tree, hash,
				NODE_DIR, &ret_node);
	aeon_dbg("%s", __func__);
	if (found == 1 && hash == ret_node->hash)
		direntry = ret_node->direntry;
	aeon_dbg("%s", __func__);

	return direntry;
}

static ino_t aeon_inode_by_name(struct inode *dir, struct qstr *entry)
{
	struct super_block *sb = dir->i_sb;
	struct aeon_dentry *direntry;

	direntry = aeon_find_dentry(sb, NULL, dir, entry->name, entry->len);

	if (direntry == NULL)
		return 0;

	return direntry->ino;
}

struct dentry *aeon_lookup(struct inode *dir, struct dentry *dentry, unsigned int flag)
{
	struct inode *inode = NULL;
	ino_t ino;

	ino = aeon_inode_by_name(dir, &dentry->d_name);

	if (ino) {
		inode = aeon_iget(dir->i_sb, ino);
		if (inode == ERR_PTR(-ESTALE) || inode == ERR_PTR(-ENOMEM)
				|| inode == ERR_PTR(-EACCES)) {
			aeon_err(dir->i_sb,
				  "%s: get inode failed: %lu\n",
				  __func__, (unsigned long)ino);
			return ERR_PTR(-EIO);
		}
	}

	return d_splice_alias(inode, dentry);
}

static int aeon_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = dir->i_sb;
	struct aeon_inode *pidir;
	struct aeon_inode update_dir;
	int ret = -ENOMEM;

	pidir = aeon_get_inode(sb, dir);

	aeon_dbg("%s: %s\n", __func__, dentry->d_name.name);
	aeon_dbg("%s: inode %lu, dir %lu\n", __func__,
				inode->i_ino, dir->i_ino);

	ret = aeon_remove_dentry(dentry, 0, &update_dir);
	if (ret)
		goto out;

	inode->i_ctime = dir->i_ctime;

	if (inode->i_nlink)
		drop_nlink(inode);
	return 0;
out:
	aeon_err(sb, "%s return %d\n", __func__, ret);
	return ret;
}

const struct inode_operations aeon_dir_inode_operations = {
	.create = aeon_create,
	.lookup = aeon_lookup,
	.unlink = aeon_unlink,
};
