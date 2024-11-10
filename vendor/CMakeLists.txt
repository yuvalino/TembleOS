include(ExternalProject)


# Toybox
set(TOYBOX_CFLAGS "-I${TVM_INCLUDE} -DTOYBOX_FORKLESS=1")
set(TOYBOX_DIR ${CMAKE_CURRENT_LIST_DIR}/toybox)
ExternalProject_Add(extern_toybox
    PREFIX              toybox
    SOURCE_DIR          ${TOYBOX_DIR}
    BINARY_DIR          toybox-build
    CONFIGURE_COMMAND   ""
    BUILD_COMMAND       ${CMAKE_COMMAND} -E env CFLAGS=${TOYBOX_CFLAGS} V=1 $(MAKE) -C ${TOYBOX_DIR}
    COMMAND             ${CMAKE_COMMAND} -E env sh -c "find ${TOYBOX_DIR} -name '*.o' | xargs ${CMAKE_AR} rcs libtoybox.a"
    BUILD_BYPRODUCTS    toybox-build/libtoybox.a
    INSTALL_COMMAND     ""
)
ExternalProject_Get_Property(extern_toybox BINARY_DIR)
add_library(toybox STATIC IMPORTED GLOBAL)
set_target_properties(toybox PROPERTIES IMPORTED_LOCATION ${BINARY_DIR}/libtoybox.a)
add_dependencies(toybox extern_toybox)

# mksh
set(MKSH_CFLAGS "-I${TVM_INCLUDE} -DMKSH_FORKLESS=1")
set(MKSH_DIR ${CMAKE_CURRENT_LIST_DIR}/mksh)
ExternalProject_Add(extern_mksh
    PREFIX              mksh
    SOURCE_DIR          ${MKSH_DIR}
    BINARY_DIR          mksh-build
    CONFIGURE_COMMAND   ""
    BUILD_COMMAND       ${CMAKE_COMMAND} -E env sh -c "! [[ -f ./Rebuild.sh ]] || sh ./Rebuild.sh"
    COMMAND             ${CMAKE_COMMAND} -E env sh -c "[[ -f ./Rebuild.sh ]] || CFLAGS=\"${MKSH_CFLAGS}\" sh ${MKSH_DIR}/Build.sh"
    COMMAND             ${CMAKE_COMMAND} -E env sh -c "find . -name '*.o' | xargs ${CMAKE_AR} rcs libmksh.a"
    BUILD_BYPRODUCTS    mksh-build/libmksh.a
    INSTALL_COMMAND     ""
)
ExternalProject_Get_Property(extern_mksh BINARY_DIR)
add_library(mksh STATIC IMPORTED GLOBAL)
set_target_properties(mksh PROPERTIES IMPORTED_LOCATION ${BINARY_DIR}/libmksh.a)
add_dependencies(mksh extern_mksh)

# dropbear
set(DROPBEAR_CFLAGS "-I${TVM_INCLUDE} -DDROPBEAR_FORKLESS=1")
set(DROPBEAR_LDFLAGS "tmp_dummy.o -o tmp_dummy.out && echo")
set(DROPBEAR_DIR ${CMAKE_CURRENT_LIST_DIR}/dropbear)
set(DROPBEAR_PROGRAMS "dropbear scp")
set(DROPBEAR_DUMMY_PROGRAM "int main() { return 0\$<SEMICOLON> }")
ExternalProject_Add(extern_dropbear
    PREFIX              dropbear
    SOURCE_DIR          ${DROPBEAR_DIR}
    BINARY_DIR          dropbear-build
    CONFIGURE_COMMAND   ${CMAKE_COMMAND} -E env CFLAGS=${DROPBEAR_CFLAGS} ${DROPBEAR_DIR}/configure
    COMMAND             ${CMAKE_COMMAND} -E echo ${DROPBEAR_DUMMY_PROGRAM} > tmp_dummy.c
    COMMAND             cp ${DROPBEAR_DIR}/localoptions.h localoptions.h
    COMMAND             $(CC) tmp_dummy.c -c -o tmp_dummy.o
    BUILD_COMMAND       ${CMAKE_COMMAND} -E env PROGRAMS=${DROPBEAR_PROGRAMS} $(MAKE) MULTI=1 LDFLAGS=${DROPBEAR_LDFLAGS}
    COMMAND             ${CMAKE_COMMAND} -E env sh -c "find . -name '*.o' | xargs ${CMAKE_AR} rcs libdropbear.a"
    BUILD_BYPRODUCTS    dropbear-build/tmp_dummy.c; dropbear-build/tmp_dummy.o; dropbear-build/tmp_dummy.out; dropbear-build/libdropbear.a
    INSTALL_COMMAND     ""
)
ExternalProject_Get_Property(extern_dropbear BINARY_DIR)
add_library(dropbear STATIC IMPORTED GLOBAL)
set_target_properties(dropbear PROPERTIES IMPORTED_LOCATION ${BINARY_DIR}/libdropbear.a)
add_dependencies(dropbear extern_dropbear)
