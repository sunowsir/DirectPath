#!/bin/bash

# --- 1. 基础环境配置 ---
export OPENWRT_STAGING=/home/openwrt/openwrt-25.12/staging_dir
export STAGING_DIR=$OPENWRT_STAGING

export BPF_SDK=/home/openwrt/llvm-bpf

# 定义交叉编译器
export CROSS_COMPILE=$OPENWRT_STAGING/toolchain-x86_64_gcc-14.3.0_musl/bin/x86_64-openwrt-linux-musl-
export CC="${CROSS_COMPILE}gcc"

# 包含路径
export TARGET_INC=$OPENWRT_STAGING/target-x86_64_musl/usr/include
export TOOLCHAIN_INC=$OPENWRT_STAGING/toolchain-x86_64_gcc-14.3.0_musl/usr/include

# 库路径 (增加 libintl-full 的搜索路径)
export LIB_DIR=$OPENWRT_STAGING/target-x86_64_musl/usr/lib
export INTL_LIB_DIR=$LIB_DIR/libintl-full/lib

# --- 2. 编译内核 BPF 程序 ---
echo "正在编译 eBPF 内核程序..."
$BPF_SDK/bin/clang -O3 -ffast-math -target bpf -g \
    -I$BPF_SDK/include \
    -I$TARGET_INC \
    -I$TOOLCHAIN_INC \
    -c tc_direct_path.c -o tc_direct_path.o

$BPF_SDK/bin/clang -O3 -ffast-math -target bpf -g \
    -I$BPF_SDK/include \
    -I$TARGET_INC \
    -I$TOOLCHAIN_INC \
    -c xdp_direct_path.c -o xdp_direct_path.o

# --- 3. 编译用户态程序 ---
echo "正在编译用户态控制程序..."
# 增加 -L$INTL_LIB_DIR 确保编译器能找到 -lintl
# 增加 -Wl,-rpath-link 确保链接器处理间接依赖时不报错
$CC -O3 import.c \
    -I$TARGET_INC \
    -L$LIB_DIR \
    -L$INTL_LIB_DIR \
    -Wl,-rpath-link=$LIB_DIR \
    -Wl,-rpath-link=$INTL_LIB_DIR \
    -lbpf -lelf -lz -lintl \
    -o import_domains

echo "编译完成！"
