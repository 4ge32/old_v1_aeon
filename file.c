#include <linux/fs.h>
#include <linux/dax.h>
#include <linux/iomap.h>
#include <linux/uio.h>

#include "aeon.h"
#include "balloc.h"
#include "inode.h"

static ssize_t aeon_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = iocb->ki_filp->f_mapping->host;
	ssize_t ret;

	if(iov_iter_count(to))
		return 0;

	inode_lock_shared(inode);
	ret = dax_iomap_rw(iocb, to, &aeon_iomap_ops);
	inode_unlock_shared(inode);

	file_accessed(iocb->ki_filp);

	return ret;
}

static ssize_t aeon_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;


	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out_unlock;
	ret = file_remove_privs(file);
	if (ret)
		goto out_unlock;
	ret = file_update_time(file);
	if (ret)
		goto out_unlock;

	ret = dax_iomap_rw(iocb, from, &aeon_iomap_ops);
	if (ret > 0 && iocb->ki_pos > i_size_read(inode)) {
		i_size_write(inode, iocb->ki_pos);
		mark_inode_dirty(inode);
	}

out_unlock:
	inode_unlock(inode);
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	return ret;
	return 0;
}

const struct file_operations aeon_dax_file_operations = {
	.read_iter  = aeon_file_read_iter,
	.write_iter = aeon_file_write_iter,
};

static int aeon_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
		            unsigned flags, struct iomap *iomap)
{
	struct aeon_sb_info *sbi = AEON_SB(inode->i_sb);
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	unsigned long first_block = 0;
	unsigned long blocknr = 1;
	unsigned long ent_blks;
	int ret;

	aeon_dbg("%s: START\n", __func__);
	ent_blks = 1;
	first_block = 10;
	ret = aeon_free_data_blocks(inode->i_sb, sih, blocknr, ent_blks);
	ret = aeon_new_data_blocks(inode->i_sb, sih, &blocknr, first_block, ent_blks, ANY_CPU);

	if (ret < 0)
		return ret;

	iomap->flags = 0;
	iomap->bdev = inode->i_sb->s_bdev;
	iomap->offset = offset;
	iomap->dax_dev = sbi->s_dax_dev;

	if (ret == 0) {
		iomap->type = IOMAP_HOLE;
		iomap->addr = IOMAP_NULL_ADDR;
		iomap->length = 0;
	} else {
		iomap->type = IOMAP_MAPPED;
		iomap->addr = ret;
		iomap->length = ret;
		iomap->flags |= IOMAP_F_MERGED;
	}

	aeon_dbg("%s: FINISH\n", __func__);
	return 0;
}

static int aeon_iomap_end(struct inode *inode, loff_t offset, loff_t length,
			  ssize_t written, unsigned flags, struct iomap *iomap)
{
	fs_put_dax(iomap->dax_dev);

	return 0;
}

const struct iomap_ops aeon_iomap_ops = {
	.iomap_begin = aeon_iomap_begin,
	.iomap_end   = aeon_iomap_end,
};
