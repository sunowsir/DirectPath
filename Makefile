# --- 1. 路径与环境配置 ---
G_HOME          := /home/sun/.podman/ubuntu/home/openwrt
OPENWRT_STAGING := $(G_HOME)/openwrt-25.12/staging_dir
export STAGING_DIR := $(OPENWRT_STAGING)

BPF_SDK := $(G_HOME)/llvm-bpf
CLANG   := $(BPF_SDK)/bin/clang

# 交叉编译器
CROSS_COMPILE := $(OPENWRT_STAGING)/toolchain-x86_64_gcc-14.3.0_musl/bin/x86_64-openwrt-linux-musl-
CC            := $(CROSS_COMPILE)gcc

# 项目目录结构
SRC_DIR     := src
INC_DIR     := include
TARGET_DIR  := target

# 编译包含路径
TARGET_INC    := $(OPENWRT_STAGING)/target-x86_64_musl/usr/include
TOOLCHAIN_INC := $(OPENWRT_STAGING)/toolchain-x86_64_gcc-14.3.0_musl/usr/include
# 增加对本地 include 目录的引用
INCLUDES      := -I$(INC_DIR) -I$(BPF_SDK)/include -I$(TARGET_INC) -I$(TOOLCHAIN_INC)

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

# --- 2. 目标文件定义 ---
# 定义最终产物的路径
BPF_PROGS     := $(TARGET_DIR)/tc_direct_path.o $(TARGET_DIR)/xdp_direct_path.o
USER_BIN      := $(TARGET_DIR)/import_domains

.PHONY: all clean bpf user prepare

# 默认目标
all: prepare bpf user
	@echo "全部编译完成！产物位于 $(TARGET_DIR)/"

# 3. 创建目标目录
prepare:
	@mkdir -p $(TARGET_DIR)

# 4. 内核态 BPF 程序规则
bpf: $(BPF_PROGS)

# 通用规则：将 src/ 下的 .c 编译为 target/ 下的 .o
$(TARGET_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "正在编译 BPF 对象: $<"
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@

# 5. 用户态程序规则
user: $(USER_BIN)

$(USER_BIN): $(SRC_DIR)/import.c
	@echo "正在编译用户态控制程序: $<"
	$(CC) $(USER_CFLAGS) $< $(INCLUDES) $(LDFLAGS) -o $@

# 6. 清理
clean:
	rm -rf $(TARGET_DIR)
	@echo "已清理 $(TARGET_DIR) 目录。"
