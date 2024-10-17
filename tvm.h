#pragma once

#define _COW_REG(Name, InitFunc) \
    static void *_tvm_rcg_ ## Name () { return (& Name); } \
    __attribute__((constructor)) \
    static void _tvm_rcc_ ## Name () { _tvm_register_cow(_tvm_rcg_ ## Name, sizeof(Name), InitFunc); }
#define _COW_REG_INIT(Name, InitExpr) \
    static void _tvm_rci_ ## Name () { Name = (InitExpr); } \
    _COW_REG(Name, _tvm_rci_ ## Name )

#define COW_IMPL_INIT(Type, Name, InitExpr) __thread Type Name; _COW_REG_INIT(Name, InitExpr)
#define COW_IMPL(Type, Name) __thread Type Name; _COW_REG(Name, NULL)
#define COW_IMPL_ARRAY(Type, Name, Size) __thread Type Name [Size]; _COW_REG(Name, NULL)
#define COW_DECL(TypeName) extern __thread TypeName
    
void _tvm_register_cow(void *(*getptr_fn)(), unsigned size, void (*init_fn)());
    
void tvm_init();

#define tvm_environ (*(_tvm_environ()))
char ***_tvm_environ();

typedef int (*main_func_t)(int, char * const*, char * const*);
void tvm_register_program(const char *pathname, main_func_t main_routine);

