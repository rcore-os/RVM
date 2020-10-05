#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>

#include <rvm.h>

static int rvm_open(struct inode* inode, struct file* file) {
    pr_info("[RVM] rvm_open\n");
    return 0;
}

static int rvm_release(struct inode* inode, struct file* file) {
    pr_info("[RVM] rvm_release\n");
    return 0;
}

static long rvm_ioctl(struct file* filp, unsigned int ioctl, unsigned long arg) {
    pr_info("[RVM] rvm_ioctl %x %lx\n", ioctl, arg);
    return -2;
}

static const struct file_operations rvm_fops = {
    .owner = THIS_MODULE,
    .open = rvm_open,
    .release = rvm_release,
    .unlocked_ioctl = rvm_ioctl,
    .llseek = no_llseek,
};

struct miscdevice rvm_device = {
    .minor = 255,
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
MODULE_DESCRIPTION("Rcore Virtual Machine.");
MODULE_VERSION("0.1.0");
