
find_path(GMPXX_INCLUDE_DIR gmpxx.h)

# TODO: get version

find_library(GMPXX_LIBRARY NAMES gmpxx)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GMPXX
    FOUND_VAR G