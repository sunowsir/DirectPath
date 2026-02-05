# --- 1. 路径配置 ---
OPENWRT_STAGING := /home/openwrt/openwrt-25.12/staging_dir
# 必须 export 环境变量，否则交叉编译器会报错
export STAGING_DIR := $(OPENWRT_STAGING)

BPF_SDK := /home/openwrt/llvm-bpf
CLANG   := $(BPF_SDK)/bin/clang

# 交叉编译器
CROSS_COMPILE := $(OPENWRT_STAGING)/toolchain-x86_64_gcc-14.3.0_musl/bin/x86_64-openwrt-linux-musl-
CC            := $(CROSS_COMPILE)gcc

# 包含路径
TARGET_INC    := $(OPENWRT_STAGING)/target-x86_64_musl/usr/include
TOOLCHAIN_INC := $(OPENWRT_STAGING)/toolchain-x86_64_gcc-14.3.0_musl/usr/include
INCLUDES      := -I$(BPF_SDK)/include -I$(TARGET_INC) -I$(TOOLCHAIN_INC)

# 库路径与链接选项
LIB_DIR       := $(OPENWRT_STAGING)/target-x86_64_musl/usr/lib
INTL_LIB_DIR  := $(LIB_DIR)/libintl-full/lib
LDFLAGS       := -L$(LIB_DIR) -L$(INTL_LIB_DIR) \
                 -Wl,-rpath-link=$(LIB_DIR) \
                 -Wl,-rpath-link=$(INTL_LIB_DIR) \
                 -lbpf -lelf -lz -lintl

# 编译选项
BPF_CFLAGS    := -O3 -ffast-math -target bpf -g
USER_CFLAGS   := -O3

# --- 2. 目标定义 ---
BPF_OBJS      := tc_direct_path.o xdp_direct_path.o
USER_BIN      := import_domains

.PHONY: all clean bpf user

all: bpf user
	@echo "全部编译完成！"

# 内核态 BPF 程序规则
bpf: $(BPF_OBJS)
	@echo "eBPF 内核程序编译完成: $^"

%.o: %.c
	@echo "正在编译 BPF 对象: $<"
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@

# 用户态程序规则
user: $(USER_BIN)
	@echo "用户态程序编译完成: $<"

$(USER_BIN): import.c
	@echo "正在编译用户态控制程序: $<"
	$(CC) $(USER_CFLAGS) $< $(INCLUDES) $(LDFLAGS) -o $@

# 清理
clean:
	rm -f $(BPF_OBJS) $(USER_BIN)
	@echo "已清理生成文件。"
