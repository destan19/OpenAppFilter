

应用过滤是一款基于OpenWrt的家长管理插件，支持游戏、视频、聊天、下载等app过滤  



### 如何编译应用过滤固件
1. 准备OpenWrt源码，并编译成功

不要使用 master 分支，因为 luci 版本不兼容，推荐18.06版本。

```shell
git clone -b openwrt-18.06 https://github.com/openwrt/openwrt.git
```

2. 进入 OpenWrt 源码根目录

```
cd ./openwrt
```

3. clone应用过滤源码到OpenWrt源码package目录

```shell
git clone https://github.com/destan19/OpenAppFilter.git package/OpenAppFilter
```

4. 生成 feeds 配置文件并加入 OpenAppFilter 依赖

参考文档：[https://openwrt.org/docs/guide-developer/helloworld/chapter4](https://openwrt.org/docs/guide-developer/helloworld/chapter4)

```shell
cp feeds.conf.default feeds.conf
echo "src-git openappfilter https://github.com/destan19/OpenAppFilter" >> feeds.conf
```

更新和安装 feeds
```
./scripts/feeds update
./scripts/feeds install -a I
```

5. 在 openwrt 根目录执行 make menuconfig 并开启应用过滤插件宏
    1. 选择 Derry Apps 项，勾选 appfilter 和 kmod-oaf

6. 编译生成固件  
    make V=s   
    
**编译产物**

```
./bin/packages/x86_64/base/appfilter_x.x-x_x86_64.ipk
```

### 使用说明
1. 将应用过滤设备做主路由  
2. 关闭软硬加速、广告过滤、QOS、多WAN等涉及到nf_conn mark的模块  
3. 开启应用过滤并选择需要过滤的app即可生效  

### 如何自定义特征码
https://zhuanlan.zhihu.com/p/419053529  

### 特征库下载地址

https://destan19.github.io    

### 演示视频 
https://www.bilibili.com/video/BV1ZL41137aT/


### OpenWrt应用过滤交流群
群号： 868508199

点击链接加入群聊【OpenWrt技术交流】：https://jq.qq.com/?_wv=1027&k=GRkd86no

### 插件截图
![](https://github.com/destan19/picture/blob/main/oaf1.jpg)

![](https://github.com/destan19/picture/blob/main/oaf2.jpg)

![](https://github.com/destan19/picture/blob/main/oaf3.jpg)


App filtering is a parent management plug-in based on OpenWrt, which supports app filtering for games, videos, chats, downloads, etc.
### How to compile application filtering firmware
1. Prepare OpenWrt source code and compile successfully  
    Recommended source code repository:  
    https://github.com/coolsnowwolf/lede.git  
    If you use the official source code, do not use the master branch, because the luci version is not compatible, version 18.06 is recommended.  
2. Clone the application filtering source code to the OpenWrt source code package directory  
git clone https://github.com/destan19/OpenAppFilter.git package/OpenAppFilter  
3. make menuconfig to open the application filter plug-in macro  
     Execute make menuconfig in the OpenWrt source code directory, enter the luci app menu and select luci-app-oaf to save  
4. Compile and generate firmware  
     make V=s  
### Instructions for use
1. Make the application filtering device the main route  
2. Turn off software and hardware acceleration, advertising filtering, QOS, multi-WAN and other modules related to nf_conn mark  
3. Turn on application filtering and select the app that needs to be filtered to take effect  

