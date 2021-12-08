

应用过滤是一款基于OpenWrt的家长管理插件，支持游戏、视频、聊天、下载等app过滤  
这是5.x源码，只对重大bug进行修复。

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
2. 关闭软硬加速、广告过滤、QOS、多WAN等涉及到nf_conn mark的模块  
3. 开启应用过滤并选择需要过滤的app即可生效  

### 如何自定义特征码
https://zhuanlan.zhihu.com/p/419053529  

### 固件和特征库下载地址
https://destan19.github.io    

### 演示视频 
https://www.bilibili.com/video/BV1ZL41137aT/

### 6.0以上版本ipk安装
1. 通过以下源码编译固件  
https://github.com/destan19/openfros  
2. 在release中下载ipk文件直接安装  

### OpenWrt应用过滤交流群
群号： 868508199

点击链接加入群聊【OpenWrt技术交流】：https://jq.qq.com/?_wv=1027&k=GRkd86no

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

