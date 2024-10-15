#pragma once

#define COW_DECL(Type, Name) extern __thread Type Name
#define COW_IMPL(Type, Name) \
    __thread Type Name; \
    static void *_tvm_rcg_ ## Name () { return (& Name); } \
    __attribute__((constructor)) \
    static void _tvm_rcc_ ## Name () { _tvm_register_cow(_tvm_rcg_ ## Name, sizeof(Name)); }
void _tvm_register_cow(void *(*getptr_fn)(), size_t size);
    
void tvm_init();

#define tvm_environ (*(_tvm_environ()))
char ***_tvm_environ();