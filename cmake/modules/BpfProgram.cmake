function(add_bpf_program NAME SRC)
    # 输出目录
    set(OBJ "${CMAKE_BINARY_DIR}/bpf/${NAME}.o")
    file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/bpf")

    # 编译 BPF
    add_custom_command(
        OUTPUT ${OBJ}
        COMMAND ${BPF_CLANG}
            -target bpf
            -O2 -g
            -I${CMAKE_SOURCE_DIR}/include
            -I${OPENWRT_TARGET_DIR}/usr/include
            -I${OPENWRT_TOOLCHAIN_DIR}/usr/include
            -c ${SRC}
            -o ${OBJ}
        DEPENDS ${SRC}
        COMMENT "Compiling BPF program ${NAME}"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        VERBATIM
    )

    # 创建 target
    set(TGT "${NAME}_bpf")
    add_custom_target(${TGT} ALL DEPENDS ${OBJ})

    # 返回 target 名称
    set(BPF_TARGETS ${BPF_TARGETS} ${TGT} PARENT_SCOPE)
endfunction()

