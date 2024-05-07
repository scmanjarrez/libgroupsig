# create an executable "demos" to run the basic tests (without compiling gtest)
add_executable(demos demos.c kty04.c ps16.c utils.c)
# if(${CMAKE_VERSION} VERSION_LESS "3.17")
#   # This code will be executed for CMake 3.16 and below
#   add_dependencies(kty04 mclproject)
# endif()
# target_include_directories(demos PUBLIC src/test/basic)
# if -DHW present, then load PYNQ dependencies as well
# We need to export LD_LIBRARY_PATH with the path to mcl -> export LD_LIBRARY_PATH=$PWD/external/lib/:$LD_LIBRARY_PATH
if (HW)
  target_link_libraries(demos kty04 ps16 crypto pynq groupsig cma pthread)
else ()
  target_link_libraries(demos kty04 ps16 groupsig)
endif ()
