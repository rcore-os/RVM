#ifndef RUST_EXTERN_H
#define RUST_EXTERN_H

#include <linux/types.h>

extern void rvm_init_logger(void);

extern bool check_hypervisor_feature(void);

extern void* new_rvm_dev(void);
extern void free_rvm_dev(const void* rvm_dev);

extern int rvm_guest_create(const void* rvm_dev);
extern int rvm_vcpu_create(const void* rvm_dev, uint64_t entry);

#endif // RUST_EXTERN_H
