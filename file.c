#include <linux/fs.h>
#include <linux/dax.h>


const struct file_operations aeon_dax_file_operations = {
	.read_iter = generic_file_read_iter,
};

