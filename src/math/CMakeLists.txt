# libmath
add_library (math STATIC nt.c rnd.c perm.c nt.h rnd.h perm.h)
target_link_libraries (math big m)
