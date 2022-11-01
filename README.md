

应用过滤是一款基于OpenWrt的家长管理插件，支持游戏、视频、聊天、下载等app过滤，比如抖音、斗鱼、王者荣耀等
### 固件下载
固件基于openwrt源码加入应用过滤插件，包含热门路由器固件，固件都是精简版，默认关闭加速等冲突模块，开启应用过滤即可生效。  
[下载固件](http://175.178.71.82:88/oaf)
### 如何自己编译应用过滤固件
1. 准备OpenWrt源码，并编译成功  
   推荐源码仓库：  
   https://github.com/coolsnowwolf/lede.git  
2. clone应用过滤源码到OpenWrt源码package目录  
git clone https://github.com/destan19/OpenAppFilter.git package/OpenAppFilter  
3. 开启oaf插件配置  
执行命令make menuconfig，进入编译配置界面，勾选luci-app-oaf后保存，  
luci-app-oaf依赖appfilter、kmod-oaf两个模块，选择luci-app-oaf后会自动选择依赖。  
4. 编译生成固件  
    make V=s   
5. 支持模式
- 主路由模式
- 旁路由模式（AP桥模式也可以使用该模式，旁路由模式仅用来过滤，如果需要完整审计功能，请部署为主路由）

### 如何安装应用过滤插件
[如何安装应用过滤插件](https://github.com/destan19/OpenAppFilter/wiki/%E5%A6%82%E4%BD%95%E5%AE%89%E8%A3%85%E5%BA%94%E7%94%A8%E8%BF%87%E6%BB%A4%E6%8F%92%E4%BB%B6)   

### 使用前必读
  1. 关闭网络加速  
  进入网络-->网络加速(ACC)菜单，将所有的勾取消并保存生效，如果是高通AX系列产品，还需要手动通过命令调整ecm慢速转发包个数，  
  调整为比较大的值，比如1000000，该值表示某条连接多少个报文进入应用过滤模块。  
  命令:  
  ```
  echo "1000000" > /sys/kernel/debug/ecm/ecm_classifier_default/accel_delay_pkts  
  ```
  注意重启后会失效，可以加入到启动脚本。  
  
  2. 关闭可能冲突的模块  
  广告过滤、QOS、多WAN等涉及到连接跟踪标记(mark)的模块可能和应用过滤冲突，测试时最好先不开启其他任何模块。  
 
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
    If you use the official source code, please switch luci to 1.0, the current code does not support luci2.0
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

