#ifndef RUST_EXTERN_H
#define RUST_EXTERN_H

#include <linux/types.h>

extern void rvm_init_logger(void);

extern bool check_hypervisor_feature(void);

extern void* new_rvm_dev(void);
extern void free_rvm_dev(const void* rvm_dev);

extern int rvm_guest_create(const void* rvm_dev);
extern int rvm_vcpu_create(const void* rvm_dev, uint64_t entry);
extern int rvm_guest_add_memory_region(const void* rvm_dev, uint64_t guest_phys_addr,
                                       uint64_t memory_size);

extern phys_addr_t rvm_gpa_to_hpa(const void* rvm_dev, uint64_t guest_phys_addr, bool alloc);

#endif // RUST_EXTERN_H
