#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>

#include <rvm.h>
#include <rust/extern.h>

static int rvm_open(struct inode* inode, struct file* file) {
    pr_info("[RVM] rvm_open\n");
    file->private_data = new_rvm_dev();
    return 0;
}

static int rvm_release(struct inode* inode, struct file* file) {
    pr_info("[RVM] rvm_release\n");
    free_rvm_dev(file->private_data);
    file->private_data = 0;
    return 0;
}

static long rvm_ioctl(struct file* filp, unsigned int ioctl, unsigned long arg) {
    pr_info("[RVM] rvm_ioctl %x %lx\n", ioctl, arg);
    return -ENOSYS;
}

static const struct file_operations rvm_fops = {
    .owner = THIS_MODULE,
    .open = rvm_open,
    .release = rvm_release,
    .unlocked_ioctl = rvm_ioctl,
    .llseek = no_llseek,
};

struct miscdevice rvm_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "rvm",
    .fops = &rvm_fops,
};

static int __init rvm_init(void) {
    int err = misc_register(&rvm_device);
    if (err) {
        pr_err("[RVM] cannot register misc device\n");
        return err;
    }

    pr_info("[RVM] module_init\n");
    rvm_init_logger();
    hello();
    return 0;
}

static void __exit rvm_exit(void) {
    misc_deregister(&rvm_device);
    pr_info("[RVM] module_exit\n");
}

module_init(rvm_init);
module_exit(rvm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yuekai Jia");
MODULE_DESCRIPTION("Rcore Virtual Machine");
MODULE_VERSION("0.1.0");
