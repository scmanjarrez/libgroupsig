include_directories ("${PROJECT_SOURCE_DIR}/src/hw")

if (HW3)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHW3")
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHW3")
endif ()

if (HW3)
  add_library (shahw STATIC file_hw.c sha3_hw.c mmio.c)
else ()
  add_library (shahw STATIC file_hw.c sha2_hw.c mmio.c)
endif ()
