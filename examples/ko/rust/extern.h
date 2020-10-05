#ifndef RUST_EXTERN_H
#define RUST_EXTERN_H

extern void hello(void);
extern void rvm_init_logger(void);
extern void* new_rvm_dev(void);
extern void free_rvm_dev(const void* ptr);

#endif // RUST_EXTERN_H
