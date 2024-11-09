include(ExternalProject)


# Toybox
set(TOYBOX_CFLAGS "-I${TVM_INCLUDE} -DTOYBOX_FORKLESS=1")
set(TOYBOX_DIR ${CMAKE_CURRENT_LIST_DIR}/toybox)
ExternalProject_Add(toybox
    PREFIX              toybox
    SOURCE_DIR          ${TOYBOX_DIR}
    BINARY_DIR          toybox-build
    CONFIGURE_COMMAND   ""
    BUILD_ALWAYS        ON
    BUILD_COMMAND       ${CMAKE_COMMAND} -E env CFLAGS=${TOYBOX_CFLAGS} V=1 $(MAKE) -C ${TOYBOX_DIR}
    COMMAND             ${CMAKE_COMMAND} -E env sh -c "find ${TOYBOX_DIR} -type file -name *.o | xargs ${CMAKE_AR} rcs libtoybox.a"
    INSTALL_COMMAND     ""
)
set_target_properties(toybox PROPERTIES IMPORTED_LOCATION toybox-build/libtoybox.a)

# mksh
set(MKSH_CFLAGS "-I${TVM_INCLUDE} -DMKSH_FORKLESS=1")
set(MKSH_DIR ${CMAKE_CURRENT_LIST_DIR}/mksh)
ExternalProject_Add(mksh
    PREFIX              mksh
    SOURCE_DIR          ${MKSH_DIR}
    BINARY_DIR          mksh-build
    CONFIGURE_COMMAND   ""
    BUILD_ALWAYS        ON
    BUILD_COMMAND       ${CMAKE_COMMAND} -E env sh -c "! [[ -f mksh-build/Rebuild.sh ]] || sh mksh-build/Rebuild.sh"
    COMMAND             ${CMAKE_COMMAND} -E env sh -c "[[ -f mksh-build/Rebuild.sh ]] || CFLAGS=\"${MKSH_CFLAGS}\" sh ${MKSH_DIR}/Build.sh"
    COMMAND             ${CMAKE_COMMAND} -E env sh -c "find ${MKSH_DIR} -type file -name *.o | xargs ${CMAKE_AR} rcs libmksh.a"
    INSTALL_COMMAND     ""
)
set_target_properties(mksh PROPERTIES IMPORTED_LOCATION mksh-build/libmksh.a)

# dropbear
set(DROPBEAR_CFLAGS "-I${TVM_INCLUDE}")
set(DROPBEAR_LDFLAGS "tmp_dummy.o -o tmp_dummy.out && echo")
set(DROPBEAR_DIR ${CMAKE_CURRENT_LIST_DIR}/dropbear)
set(DROPBEAR_DUMMY_PROGRAM "int main() { return 0\$<SEMICOLON> }")
ExternalProject_Add(dropbear
    PREFIX              dropbear
    SOURCE_DIR          ${DROPBEAR_DIR}
    BINARY_DIR          dropbear-build
    CONFIGURE_COMMAND   ${CMAKE_COMMAND} -E env CFLAGS=${DROPBEAR_CFLAGS} ${DROPBEAR_DIR}/configure
    COMMAND             ${CMAKE_COMMAND} -E echo ${DROPBEAR_DUMMY_PROGRAM} > tmp_dummy.c
    COMMAND             $(CC) tmp_dummy.c -c -o tmp_dummy.o
    BUILD_ALWAYS        ON
    BUILD_COMMAND       ${CMAKE_COMMAND} -E env $(MAKE) PROGRAMS="dropbear scp" MULTI=1 LDFLAGS=${DROPBEAR_LDFLAGS}
    COMMAND             ${CMAKE_COMMAND} -E env sh -c "find . -type file -name *.o | xargs ${CMAKE_AR} rcs libdropbear.a"
    BUILD_BYPRODUCTS    tmp_dummy.c; tmp_dummy.o; tmp_dummy.out
    INSTALL_COMMAND     ""
)
set_target_properties(dropbear PROPERTIES IMPORTED_LOCATION dropbear-build/libdropbear.a)