cmake_minimum_required(VERSION 3.18)
project(directpath C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")
include(BpfProgram)

# -------------------
# OpenWrt 目录
# -------------------
set(OPENWRT_TARGET_DIR "${OPENWRT_SDK}/staging_dir/target-x86_64_musl")
set(OPENWRT_TOOLCHAIN_DIR "${OPENWRT_SDK}/staging_dir/toolchain-x86_64_gcc-14.3.0_musl")

# -------------------
# BPF clang
# -------------------
set(BPF_SDK "${OPENWRT_SDK}/staging_dir/host/llvm-bpf")
set(BPF_CLANG "${BPF_SDK}/bin/clang")
message(STATUS "Using BPF clang: ${BPF_CLANG}")

# -------------------
# BPF 程序
# -------------------
file(GLOB TC_BPF "bpf/tc/*.c")
file(GLOB XDP_BPF "bpf/xdp/*.c")

set(BPF_TARGETS "")
foreach(src ${TC_BPF} ${XDP_BPF})
    get_filename_component(name ${src} NAME_WE)
    add_bpf_program(${name} ${src})
endforeach()

# -------------------
# 用户态程序
# -------------------
file(GLOB USER_SRC "user/*.c")
add_executable(import ${USER_SRC})

# Include directories
target_include_directories(import PRIVATE
    include
    ${OPENWRT_TOOLCHAIN_DIR}/usr/include       # Toolchain 头文件 (linux/bpf.h)
    ${OPENWRT_TARGET_DIR}/usr/include          # Target 头文件 (libbpf.h)
)

target_include_directories(import PRIVATE
    include
    ${OPENWRT_TARGET_DIR}/usr/include
    ${OPENWRT_TOOLCHAIN_DIR}/usr/include
)

# rpath-link libintl
set(INTL_DIR "${OPENWRT_TARGET_DIR}/usr/lib/libintl-full/lib")
if(EXISTS "${INTL_DIR}")
    target_link_directories(import PRIVATE ${INTL_DIR})
    target_link_options(import PRIVATE "LINKER:-rpath-link=${INTL_DIR}")
endif()

# 链接库
target_link_libraries(import PRIVATE bpf z)

# 用户态依赖 BPF 编译完成
add_dependencies(import ${BPF_TARGETS})

