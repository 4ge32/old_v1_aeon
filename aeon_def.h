#ifndef _LINUX_AEON_FS_H
#define _LINUX_AEON_FS_H

#include <linux/types.h>
#include <linux/magic.h>

#define AEON_MAGIC 0xEFF10

#define AEON_INODE_SIZE 128
#define AEON_DEF_BLOCK_SIZE_4K 4096

/* Write ordering */
#define CACHELINE_SIZE  (64)
#define CACHELINE_MASK  (~(CACHELINE_SIZE - 1))
#define CACHELINE_ALIGN(addr) (((addr)+CACHELINE_SIZE-1) & CACHELINE_MASK)

/*
 * Mount flags
 */
#define AEON_MOUNT_PROTECT      0x000001    /* wprotect CR0.WP */
#define AEON_MOUNT_XATTR_USER   0x000002    /* Extended user attributes */
#define AEON_MOUNT_POSIX_ACL    0x000004    /* POSIX Access Control Lists */
#define AEON_MOUNT_DAX          0x000008    /* Direct Access */
#define AEON_MOUNT_ERRORS_CONT  0x000010    /* Continue on errors */
#define AEON_MOUNT_ERRORS_RO    0x000020    /* Remount fs ro on errors */
#define AEON_MOUNT_ERRORS_PANIC 0x000040    /* Panic on errors */
#define AEON_MOUNT_HUGEMMAP     0x000080    /* Huge mappings with mmap */
#define AEON_MOUNT_HUGEIOREMAP  0x000100    /* Huge mappings with ioremap */
#define AEON_MOUNT_FORMAT       0x000200    /* was FS formatted on mount? */

static inline bool arch_has_clwb(void)
{
	return static_cpu_has(X86_FEATURE_CLWB);
}

extern int support_clwb;

#define _mm_clflush(addr)\
	asm volatile("clflush %0" : "+m" (*(volatile char *)(addr)))
#define _mm_clflushopt(addr)\
	asm volatile(".byte 0x66; clflush %0" : "+m" \
		     (*(volatile char *)(addr)))
#define _mm_clwb(addr)\
	asm volatile(".byte 0x66; xsaveopt %0" : "+m" \
		     (*(volatile char *)(addr)))

/* Provides ordering from all previous clflush too */
static inline void PERSISTENT_MARK(void)
{
	/* TODO: Fix me. */
}

static inline void PERSISTENT_BARRIER(void)
{
	asm volatile ("sfence\n" : : );
}

static inline void aeon_flush_buffer(void *buf, uint32_t len, bool fence)
{
	uint32_t i;

	len = len + ((unsigned long)(buf) & (CACHELINE_SIZE - 1));
	if (support_clwb) {
		for (i = 0; i < len; i += CACHELINE_SIZE)
			_mm_clwb(buf + i);
	} else {
		for (i = 0; i < len; i += CACHELINE_SIZE)
			_mm_clflush(buf + i);
	}
	/* Do a fence only if asked. We often don't need to do a fence
	 * immediately after clflush because even if we get context switched
	 * between clflush and subsequent fence, the context switch operation
	 * provides implicit fence.
	 */
	if (fence)
		PERSISTENT_BARRIER();
}

/*
 * Structure of an inode in AEON.
 */
struct aeon_inode {
	/* first 40 bytes */
	u8	i_rsvd;		 /* reserved. used to be checksum */
	u8	valid;		 /* Is this inode valid? */
	u8	deleted;	 /* Is this inode deleted? */
	u8	i_blk_type;	 /* data block size this inode uses */
	__le32	i_flags;	 /* Inode flags */
	__le64	i_size;		 /* Size of data in bytes */
	__le32	i_ctime;	 /* Inode modification time */
	__le32	i_mtime;	 /* Inode b-tree Modification time */
	__le32	i_atime;	 /* Access time */
	__le16	i_mode;		 /* File mode */
	__le16	i_links_count;	 /* Links count */

	__le64	i_xattr;	 /* Extended attribute block */

	/* second 40 bytes */
	__le32	i_uid;		 /* Owner Uid */
	__le32	i_gid;		 /* Group Id */
	__le32	i_generation;	 /* File version (for NFS) */
	__le32	i_create_time;	 /* Create time */
	__le64	aeon_ino;	 /* aeon inode number */

	__le64	log_head;	 /* Log head pointer */
	__le64	log_tail;	 /* Log tail pointer */

	/* last 40 bytes */
	__le64	alter_log_head;	 /* Alternate log head pointer */
	__le64	alter_log_tail;	 /* Alternate log tail pointer */

	__le64	create_epoch_id; /* Transaction ID when create */
	__le64	delete_epoch_id; /* Transaction ID when deleted */

	struct {
		__le32 rdev;	 /* major/minor # */
	} dev;			 /* device inode */

	__le32	csum;            /* CRC32 checksum */

	/* Leave 8 bytes for inode table tail pointer */
	__le64  pad;
} __attribute((__packed__));

#define AEON_SB_SIZE 512       /* must be power of two */


/*
 * Structure of the super block in aeon
 */
struct aeon_super_block {
	/* static fields. they never change after file system creation.
	 * checksum only validates up to s_start_dynamic field below */
	__le16		s_sum;              /* checksum of this sb */
	__le32		s_magic;            /* magic signature */
	__le32		s_blocksize;        /* blocksize in bytes */
	__le64		s_size;             /* total size of fs in bytes */

	__le64		s_start_dynamic;

	/* all the dynamic fields should go here */
	/* s_mtime and s_wtime should be together and their order should not be
	 * changed. we use an 8 byte write to update both of them atomically */
	__le32		s_mtime;            /* mount time */
	__le32		s_wtime;            /* write time */
	/* fields for fast mount support. Always keep them together */
	__le64		s_num_free_blocks;
} __attribute((__packed__));

#define AEON_NAME_LEN 512

struct aeon_dentry {
	u8	entry_type;
	u8	name_len;		/* length of the dentry name */
	u8	reassigned;		/* Currently deleted */
	u8	invalid;		/* Invalid now? */
	__le16	de_len;			/* length of this dentry */
	__le16	links_count;
	__le32	mtime;			/* For both mtime and ctime */
	__le32	csum;			/* entry checksum */
	__le64	ino;			/* inode no pointed to by this entry */
	__le64	padding;
	__le64	epoch_id;
	__le64	trans_id;
	char	name[AEON_NAME_LEN + 1];	/* File name */
} __attribute((__packed__));

#define AEON_ROOT_INO		(1)
#define AEON_INODETABLE_INO	(2)

#endif
