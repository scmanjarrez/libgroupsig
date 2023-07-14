if (ALL)
  # libgcrypto
  add_library (gcrypto STATIC spk.c prf.c)
  target_link_libraries (gcrypto PRIVATE ${OPENSSL_LIBRARIES})
endif()
