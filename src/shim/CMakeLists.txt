# libbig
add_library (big STATIC bigz.c)
target_link_libraries(big
  ${OPENSSL_LIBRARIES})

# libbase64
add_library (base64 STATIC base64.c)

# libpbcext
add_library (pbcext STATIC pbc_ext.c)
target_include_directories (pbcext
  PUBLIC
  ${MCL_INCLUDE_DIR})
target_link_libraries (pbcext
  ${MCL384_256_LIBRARY}
  ${MCL_LIBRARY})
# libhash
add_library (hash STATIC hash.c)
target_include_directories (hash
  PUBLIC
  ${OPENSSL_INCLUDE_DIR})
target_link_libraries (hash
  misc
  ${OPENSSL_LIBRARIES})
