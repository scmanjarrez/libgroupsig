add_library (misc STATIC
  misc.c
  misc.h
  profile.c
  profile.h)

target_link_libraries (misc PUBLIC base64 m)
