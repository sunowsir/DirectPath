# DirectPath 加速引擎
> DirectPath加速引擎包括：
> 1. 直连流量加速引擎：利用ebpf实现国内IP流量快速转发
> 2. 直连DNS加速引擎：利用ebpf实现国内域名DNS请求不受openclash等软件的控制直达openwrt上部署的dns服务器
> 

## 部署方法
  > 若执`check_ip_cache.sh`发现IP缓存急速上涨并爆满，大概率是内网的P2P或PCDN服务导致

  1. `git clone https://github.com/sunowsir/DirectPath.git && cd DirectPath`
  2. `export OPENWRT_SDK=openwrt源码编译目录`、`export STAGING_DIR=${OPENWRT_SDK}/staging_dir`
  3. 编译: 

    1. `cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/openwrt.cmake -DOPENWRT_SDK=$OPENWRT_SDK` 
    2. `cmake --build build -j`

  4. 拷贝编译产物至openwrt: `scp ./build/bpf/*.o ./build/import root@openwrt地址:~/path/to/`
  5. 拷贝其他脚本至openwrt: `scp ./script/* root@openwrt地址:~/path/to/`
  6. 部署: `./deploy_direct_path.sh start`
  7. 载入国内IP库和域名库: `./load_rules.sh`

## 恢复环境

  1. `./deploy_direct_path.sh stop`
  
## 调试信息 

  1. 查看调试信息，可将代码中的打印打开，然后在`openwrt`设备上执行：`cat /sys/kernel/debug/tracing/trace_pipe`
  2. 查看IP缓存利用率信息:`check_ip_cache.sh`
  3. 查看域名缓存利用率信息:`check_domain_cache.sh`
  4. 查看IP缓存内容: `monitor_hotpath_cache.sh`
  5. 查看域名缓存内容: `monitor_domain_cache.sh`

## 计划/目标
  > 暂无单独包装为某个发行版软件包或者openwrt带界面的插件的计划

  1. 支持IPv6

## 声明 :warning:

  1. 请详细阅读代码，根据自身需求修改宏定义配置以及其他代码，请勿直接使用，后果自负
