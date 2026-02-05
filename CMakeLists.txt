cmake_minimum_required(VERSION 3.10)

# --- 环境配置 ---
set(G_HOME "/home/sun/.podman/ubuntu/home/openwrt")
set(OPENWRT_STAGING "${G_HOME}/openwrt-25.12/staging_dir")
set(BPF_SDK "${G_HOME}/llvm-bpf")

# 编译阶段：使用 Launcher
set(CMAKE_C_COMPILER_LAUNCHER ${CMAKE_COMMAND} -E env STAGING_DIR=${OPENWRT_STAGING})
# 链接阶段：CMake 本身没有 LINKER_LAUNCHER，所以我们直接把变量注入到链接指令前缀中
set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_COMMAND> -E env STAGING_DIR=${OPENWRT_STAGING} <CMAKE_C_COMPILER> <FLAGS> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")

set(CMAKE_C_COMPILER "${OPENWRT_STAGING}/toolchain-x86_64_gcc-14.3.0_musl/bin/x86_64-openwrt-linux-musl-gcc")

project(DirectPath C)

# ---  路径与工具定义 ---
set(BPF_CLANG "${BPF_SDK}/bin/clang")
set(TARGET_INC "${OPENWRT_STAGING}/target-x86_64_musl/usr/include")
set(TOOLCHAIN_INC "${OPENWRT_STAGING}/toolchain-x86_64_gcc-14.3.0_musl/usr/include")
set(LIB_DIR "${OPENWRT_STAGING}/target-x86_64_musl/usr/lib")
set(INTL_LIB_DIR "${LIB_DIR}/libintl-full/lib")

# --- 自动扫描源码 ---
# 内核态：匹配 tc_ 或 xdp_ 开头的文件
file(GLOB BPF_SOURCES "src/tc_*.c" "src/xdp_*.c")
# 用户态：匹配 import.c 或其他非 BPF 文件
file(GLOB USER_SOURCES "src/import.c")

# --- BPF 编译函数封装 ---
function(add_bpf_programs)
    foreach(SRC ${ARGN})
        get_filename_component(NAME ${SRC} NAME_WE)
        set(OUTPUT_OBJ "${CMAKE_BINARY_DIR}/${NAME}.o")
        
        add_custom_command(
            OUTPUT ${OUTPUT_OBJ}
            COMMAND ${BPF_CLANG} -O3 -ffast-math -target bpf -g
                    -I${CMAKE_CURRENT_SOURCE_DIR}/include 
                    -I${BPF_SDK}/include 
                    -I${TARGET_INC} 
                    -I${TOOLCHAIN_INC} 
                    -c ${SRC} -o ${OUTPUT_OBJ}
            DEPENDS ${SRC}
        )
        list(APPEND BPF_OBJS ${OUTPUT_OBJ})
        set(BPF_ALL_OBJECTS ${BPF_OBJS} PARENT_SCOPE)
    endforeach()
endfunction()

# 执行 BPF 编译任务
add_bpf_programs(${BPF_SOURCES})
add_custom_target(bpf_progs ALL DEPENDS ${BPF_ALL_OBJECTS})

# --- 用户态程序编译 ---
add_executable(import ${USER_SOURCES})

target_include_directories(import PRIVATE 
    include 
    ${BPF_SDK}/include 
    ${TARGET_INC} 
    ${TOOLCHAIN_INC}
)

target_link_directories(import PRIVATE ${LIB_DIR} ${INTL_LIB_DIR})

target_link_libraries(import PRIVATE bpf elf z intl)

target_link_options(import PRIVATE 
    "LINKER:-rpath-link=${LIB_DIR}"
    "LINKER:-rpath-link=${INTL_LIB_DIR}"
)
