

应用过滤是一款基于OpenWrt的家长管理插件，支持游戏、视频、聊天、下载等app过滤  


### 如何编译应用过滤固件
1. 准备OpenWrt源码，并编译成功  
   推荐源码仓库：  
   https://github.com/coolsnowwolf/lede.git  
   如果用官方源码，不要用master分支，因为luci版本不兼容，推荐18.06版本。  
2. clone应用过滤源码到OpenWrt源码package目录  
git clone https://github.com/destan19/OpenAppFilter.git package/OpenAppFilter  
3. make menuconfig 开启应用过滤插件宏  
    在OpenWrt源码目录执行make menuconfig，
    勾选luci-app-oaf、appfilter、kmod-oaf三个插件并保存，其中appfilter和kmod-oaf位于Derry Apps目录，为了后续支持插件安装，luci不再强制依赖kmod-oaf模块。
4. 编译生成固件  
    make V=s   
### 使用说明
  使用前需要关闭软硬加速、广告过滤、QOS、多WAN等涉及到nf_conn mark的模块,高通的AX系列产品需要将ecm允许慢速转发的包个数调整到最大值，直接stop ecm会导致吞吐非常低。  
  最新版本已经支持旁路由模式
 
### 特征库下载地址
https://destan19.github.io/feature/

### 插件截图
![](https://github.com/destan19/picture/blob/main/oaf1.jpg)

![](https://github.com/destan19/picture/blob/main/oaf2.jpg)

![](https://github.com/destan19/picture/blob/main/oaf3.jpg)

![](https://github.com/destan19/picture/blob/main/oaf4.jpg)

![](https://github.com/destan19/picture/blob/main/oaf5.jpg)

![](https://github.com/destan19/picture/blob/main/oaf6.jpg)

App filtering is a parent management plug-in based on OpenWrt, which supports app filtering for games, videos, chats, downloads, etc.
### How to compile application filtering firmware
1. Prepare OpenWrt source code and compile successfully  
    Recommended source code repository:  
    https://github.com/coolsnowwolf/lede.git  
    If you use the official source code, do not use the master branch, because the luci version is not compatible, version 18.06 is recommended.  
2. Clone the application filtering source code to the OpenWrt source code package directory  
git clone https://github.com/destan19/OpenAppFilter.git package/OpenAppFilter  
3. make menuconfig to open the application filter plug-in macro  
     Execute make menuconfig in the OpenWrt source code directory, select luci-app-oaf,appfilter and kmod-oaf 
4. Compile and generate firmware  
     make V=s  
### Instructions for use
1. Make the application filtering device the main route  
2. Turn off software and hardware acceleration, advertising filtering, QOS, multi-WAN and other modules related to nf_conn mark  
3. Turn on application filtering and select the app that needs to be filtered to take effect  

