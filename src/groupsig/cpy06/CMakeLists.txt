include_directories ("${PROJECT_SOURCE_DIR}/src/include"
                     "${PROJECT_SOURCE_DIR}/src/global")
if (HW)
  add_library (cpy06 grp_key.c grp_key.h mgr_key.c mgr_key.h mem_key.c
    mem_key.h signature.c signature.h setup.c
    join_mem.c join_mgr.c open.c reveal.c trace.c claim.c
    claim_verify.c gml.c gml.h
    crl.c crl.h proof.c proof.h identity.c identity.h trapdoor.c trapdoor.h)
else ()
  add_library (cpy06 grp_key.c grp_key.h mgr_key.c mgr_key.h mem_key.c
    mem_key.h signature.c signature.h setup.c
    join_mem.c join_mgr.c sign.c verify.c open.c reveal.c trace.c claim.c
    claim_verify.c prove_equality.c prove_equality_verify.c gml.c gml.h
    crl.c crl.h proof.c proof.h identity.c identity.h trapdoor.c trapdoor.h)
endif ()

target_include_directories (cpy06 PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries (cpy06 PRIVATE ${OPENSSL_LIBRARIES})
