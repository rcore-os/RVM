#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <rust/extern.h>
#include <rvm.h>

extern void* __phys_to_virt(phys_addr_t address) { return phys_to_virt(address); }
extern phys_addr_t __virt_to_phys(volatile void* address) { return virt_to_phys(address); }
extern void __BUG(void) { BUG(); }

static int rvm_open(struct inode* inode, struct file* file) {
    pr_info("[RVM] rvm_open\n");
    file->private_data = new_rvm_dev();
    return 0;
}

static int rvm_release(struct inode* inode, struct file* file) {
    pr_info("[RVM] rvm_release\n");
    free_rvm_dev(file->private_data);
    file->private_data = NULL;
    return 0;
}

static long rvm_ioctl(struct file* filp, unsigned int ioctl, unsigned long arg) {
    void* rvm_dev = filp->private_data;
    void __user* argp = (void __user*)arg;
    int ret;

    switch (ioctl) {
    case RVM_GUEST_CREATE:
        return rvm_guest_create(rvm_dev);
    case RVM_GUEST_ADD_MEMORY_REGION: {
        struct rvm_guest_add_memory_region_args args;
        void* hva;

        if (copy_from_user(&args, argp, sizeof(args)))
            return -EFAULT;
        if (args.vmid != 0)
            return -EINVAL;

        hva = (void*)vm_mmap(filp, 0, args.memory_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                             args.guest_phys_addr);
        if (IS_ERR(hva))
            return PTR_ERR(hva);

        ret = rvm_guest_add_memory_region(rvm_dev, args.guest_phys_addr, args.memory_size);
        if (ret < 0) {
            vm_munmap((unsigned long)hva, args.memory_size);
            return ret;
        }

        args.userspace_addr = hva;
        copy_to_user(argp, &args, sizeof(args));
        return 0;
    }
    case RVM_GUEST_SET_TRAP: {
        struct rvm_guest_set_trap_args args;
        if (copy_from_user(&args, argp, sizeof(args)))
            return -EFAULT;
        if (args.vmid != 0)
            return -EINVAL;
        return rvm_guest_set_trap(rvm_dev, args.kind, args.addr, args.size, args.key);
    }
    case RVM_VCPU_CREATE: {
        struct rvm_vcpu_create_args args;
        if (copy_from_user(&args, argp, sizeof(args)))
            return -EFAULT;
        if (args.vmid != 0)
            return -EINVAL;
        return rvm_vcpu_create(rvm_dev, args.entry);
    }
    case RVM_VCPU_RESUME: {
        struct rvm_vcpu_resume_args args;
        if (copy_from_user(&args, argp, sizeof(args)))
            return -EFAULT;

        ret = rvm_vcpu_resume(rvm_dev, args.vcpu_id, &args.packet);
        if (ret < 0)
            return ret;

        copy_to_user(argp, &args, sizeof(args));
        return 0;
    }
    case RVM_VCPU_READ_STATE: {
        struct rvm_vcpu_state_args args;
        struct rvm_vcpu_state state;
        if (copy_from_user(&args, argp, sizeof(args)))
            return -EFAULT;
        if (args.kind != RVM_VCPU_STATE || args.buf_size != sizeof(state))
            return -EINVAL;

        ret = rvm_vcpu_read_state(rvm_dev, args.vcpu_id, &state);
        if (ret < 0)
            return ret;

        copy_to_user(args.vcpu_state_ptr, &state, sizeof(state));
        return 0;
    }
    case RVM_VCPU_WRITE_STATE: {
        struct rvm_vcpu_state_args args;
        if (copy_from_user(&args, argp, sizeof(args)))
            return -EFAULT;

        switch (args.kind) {
        case RVM_VCPU_STATE: {
            struct rvm_vcpu_state state;
            if (args.buf_size != sizeof(state))
                return -EINVAL;
            if (copy_from_user(&state, args.vcpu_state_ptr, sizeof(state)))
                return -EFAULT;
            return rvm_vcpu_write_state(rvm_dev, args.vcpu_id, &state);
        }
        case RVM_VCPU_IO: {
            struct rvm_vcpu_io state;
            if (args.buf_size != sizeof(state))
                return -EINVAL;
            if (copy_from_user(&state, args.vcpu_io_ptr, sizeof(state)))
                return -EFAULT;
            return rvm_vcpu_write_io_state(rvm_dev, args.vcpu_id, &state);
        }
        default:
            return -EINVAL;
        }
    }
    case RVM_VCPU_INTERRUPT: {
        struct rvm_vcpu_interrupt_args args;
        if (copy_from_user(&args, argp, sizeof(args)))
            return -EFAULT;
        return rvm_vcpu_interrupt(rvm_dev, args.vcpu_id, args.vector);
    }
    default:
        return -EINVAL;
    }
}

static vm_fault_t rvm_user_vm_fault(struct vm_fault* vmf) {
    void* rvm_dev = vmf->vma->vm_file->private_data;
    uint64_t guest_phys_addr = vmf->pgoff << PAGE_SHIFT;
    struct page* page;

    phys_addr_t page_pa = rvm_gpa_to_hpa(rvm_dev, guest_phys_addr, true);
    if (page_pa == 0)
        return VM_FAULT_SIGBUS;

    page = pfn_to_page(page_pa >> PAGE_SHIFT);
    get_page(page);
    vmf->page = page;
    return 0;
}

static const struct vm_operations_struct rvm_user_vm_ops = {
    .fault = rvm_user_vm_fault,
};

static int rvm_mmap(struct file* filp, struct vm_area_struct* vma) {
    vma->vm_ops = &rvm_user_vm_ops;
    return 0;
}

static const struct file_operations rvm_fops = {
    .owner = THIS_MODULE,
    .open = rvm_open,
    .release = rvm_release,
    .unlocked_ioctl = rvm_ioctl,
    .llseek = no_llseek,
    .mmap = rvm_mmap,
};

struct miscdevice rvm_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "rvm",
    .fops = &rvm_fops,
};

static int __init rvm_init(void) {
    int err;
    if (!check_hypervisor_feature()) {
        pr_err("[RVM] no hardware support\n");
        return -ENOSYS;
    }
    err = misc_register(&rvm_device);
    if (err) {
        pr_err("[RVM] cannot register misc device\n");
        return err;
    }

    pr_info("[RVM] module_init\n");
    rvm_init_logger();
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
