#include <linux/fs.h>



static int aeon_create(struct inode *dir, struct dentry *dentry, umode_t mode,
			bool excl)
{
	return 0;
}

static struct dentry *aeon_lookup(struct inode *dir, struct dentry *dentry, unsigned int flag)
{
	return NULL;
}

const struct inode_operations nova_dir_inode_operations = {
	.create = aeon_create,
	.lookup = aeon_lookup,
};
