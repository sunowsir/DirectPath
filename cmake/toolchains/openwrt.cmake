set(CMAKE_SYSTEM_NAME Linux)

# ⭐ 关键：让 try_compile 继承变量
set(CMAKE_TRY_COMPILE_PLATFORM_VARIABLES OPENWRT_SDK)

# -------- SDK Root --------

if(DEFINED OPENWRT_SDK)
    set(_OPENWRT_SDK "${OPENWRT_SDK}")
elseif(DEFINED ENV{OPENWRT_SDK})
    set(_OPENWRT_SDK "$ENV{OPENWRT_SDK}")
else()
    message(FATAL_ERROR "OPENWRT_SDK not set")
endif()

set(OPENWRT_SDK "${_OPENWRT_SDK}" CACHE PATH "")

# -------- staging --------

set(STAGING_DIR "${OPENWRT_SDK}/staging_dir")

# -------- Toolchain detection --------

file(GLOB TOOLCHAIN_DIR
    "${STAGING_DIR}/toolchain-*"
)

list(GET TOOLCHAIN_DIR 0 TOOLCHAIN_PATH)

# -------- Compiler --------

file(GLOB GCC_BIN
    "${TOOLCHAIN_PATH}/bin/*-gcc"
)

list(GET GCC_BIN 0 GCC_PATH)

set(CMAKE_C_COMPILER "${GCC_PATH}")

# -------- Target sysroot --------

file(GLOB TARGET_DIR
    "${STAGING_DIR}/target-*"
)

list(GET TARGET_DIR 0 TARGET_PATH)

set(CMAKE_SYSROOT "${TARGET_PATH}")

# -------- Environment --------

set(CMAKE_C_COMPILER_LAUNCHER
    ${CMAKE_COMMAND} -E env STAGING_DIR=${STAGING_DIR}
)

set(CMAKE_FIND_ROOT_PATH "${TARGET_PATH}")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_SYSROOT_COMPILE ${CMAKE_SYSROOT})
set(CMAKE_SYSROOT_LINK ${CMAKE_SYSROOT})

set(CMAKE_C_FLAGS_INIT "--sysroot=${CMAKE_SYSROOT}")
set(CMAKE_EXE_LINKER_FLAGS_INIT "--sysroot=${CMAKE_SYSROOT}")

set(CMAKE_C_STANDARD_INCLUDE_DIRECTORIES
    ${TOOLCHAIN_PATH}/include
    ${TARGET_PATH}/usr/include
)

set(ENV{PKG_CONFIG_SYSROOT_DIR} ${STAGING_DIR})
set(ENV{PKG_CONFIG_PATH} ${STAGING_DIR}/target-*/usr/lib/pkgconfig)

