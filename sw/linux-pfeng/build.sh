#编译master驱动
echo "开始编译"
make PFE_CFG_MULTI_INSTANCE_SUPPORT=1 PFE_CFG_PFE_MASTER=1 PFE_CFG_TARGET_ARCH_aarch64=1 KERNELDIR=/home/lc/work/s32g/s32g399a/linux/ PLATFORM=/home/lc/work/tools/arm-gnu-toolchain-11.3.rel1-x86_64-aarch64-none-linux-gnu/bin/aarch64-none-linux-gnu all
echo "编译完成"

ls pfeng.ko -alh

#去除调试信息
echo "去除调试信息"
/home/lc/work/tools/arm-gnu-toolchain-11.3.rel1-x86_64-aarch64-none-linux-gnu/bin/aarch64-none-linux-gnu-strip --strip-debug pfeng.ko

ls pfeng.ko -alh
