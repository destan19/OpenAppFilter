
## 应用过滤(OAF)
应用过滤是一款OpenWrt防沉迷插件，支持热门的游戏、视频、聊天等APP，比如抖音、斗鱼、王者荣耀等，目前支持了几百款APP，可访问[www.openappfilter.com](http://www.openappfilter.com)查看详细的介绍  

## 如何编译  
1. 准备一套OpenWrt源码并已经完成固件编译  
OpenWrt源码编译可自行查找教程，不在这里讲解  
2. 下载应用过滤源码  
进入OpenWrt源码根目录执行以下命令下载源码  
```
git clone https://github.com/destan19/OpenAppFilter.git package/OpenAppFilter    
```
3. 开启应用过滤编译选项  
应用过滤包括三个源码包，分别对应页面、服务和内核模块  
编译前需要开启者三个包的编译选项，可以通过make  menuconfig图形界面选择luci-app-oaf，  
也可以按照以下命令生成(在源码根目录执行):  
```
echo "CONFIG_PACKAGE_luci-app-oaf=y" >>.config  
make defconfig  
```
这样就会自动开启三个模块的编译选项  

4. 开始编译插件  
如果之前的openwrt源码已经编译成功只需要编译单个插件即可  
```
     make package/luci-app-oaf/compile V=s  
     make package/open-app-filter/compile V=s
     make package/oaf/compile V=s
```
也可以重新编译整个固件，这样插件会集成到固件中
```
make V=s
```


## OAF(Open App Filter)  
OAF is a parental control plug-in based on OpenWrt, which supports app filtering for games, videos, chats, downloads, such as Tiktok, Youtube, Telegram,etc.,and support self-defined app rules, you can lean more and download firmware by visiting [www.openappfilter.com](http://www.openappfilter.com) .


### Preparation
- Prepare a router that supports openwrt  
There are already many routers that support the openwrt system, you can choose a simple one for installation,[See which devices support](https://openwrt.org).  
- Install the openwrt system on your router  
The openwrt install tutorial can be found through the [forum](https://forum.openwrt.org).  
### How to compile OAF  
1. Prepare OpenWrt source or SDK and compile successfully   
#### general steps  
```
   git clone https://github.com/openwrt/openwrt
   cd openwrt
   ./scripts/feeds update -a
   ./scripts/feeds install -a
   make defconfig
   make V=s
```   
2. Download OAF source code  
git clone https://github.com/destan19/OpenAppFilter.git package/OpenAppFilter    
3. Open the compile configuration   
```
     echo "CONFIG_PACKAGE_luci-app-oaf=y" >>.config  
     make defconfig  
```
4. Begin compile  
- Compile OAF separately  
```
     make package/luci-app-oaf/compile V=s  
```
- Compile the entire firmware  
```
     make V=s  
```



