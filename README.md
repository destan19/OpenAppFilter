

应用过滤是一款基于OpenWrt的家长管理插件，支持游戏、视频、聊天、下载等app过滤  


### 如何编译应用过滤固件
1. 准备OpenWrt源码，并编译成功  
   推荐源码仓库：  
   https://github.com/coolsnowwolf/lede.git  
   如果用官方源码，不要用master分支，因为luci版本不兼容，推荐18.06版本。  
2. clone应用过滤源码到OpenWrt源码package目录  
git clone https://github.com/destan19/OpenAppFilter.git package/OpenAppFilter  
3. make menuconfig 开启应用过滤插件宏  
    在OpenWrt源码目录执行make menuconfig，进入luci app菜单选择luci-app-oaf保存  
4. 编译生成固件  
    make V=s   
### 使用说明
1. 将应用过滤设备做主路由 
2. 关闭软硬加速、广告过滤、QOS、多WAN等涉及到nf_conn mark的模块,高通的AX系列产品需要将ecm允许慢速转发的包个数调整到最大值，直接stop ecm会导致吞吐非常低。
3. 开启应用过滤并选择需要过滤的app即可生效  

### 如何自定义特征码
https://zhuanlan.zhihu.com/p/419053529  

### 特征库下载地址
https://destan19.github.io/feature/

### 深度优化的上网行为管理系统FROS  
基于OpenAppFilter开发了一套行为管理系统，全新架构  
支持应用过滤、网址过滤、端口过滤、防沉迷、游戏记录等  
官网： www.ifros.cn  

### 演示视频 
抖音(douyin)号： linux4096 (linux开发者-derry)  

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

