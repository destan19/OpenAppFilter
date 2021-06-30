
### 插件和特征库发布地址

https://destan19.github.io/
### OpenAppFilter功能简介

OpenAppFilter基于数据流深度识别技术，可以实现游戏、视频、直播等app过滤和审计。

### 过滤效果演示视频
https://www.bilibili.com/video/BV11z4y1z7tQ/  

	
### 插件截图
#### 1
![main1](https://destan19.github.io/assets/img/oaf/oaf1.png)

#### 2
![main1](https://destan19.github.io/assets/img/oaf/oaf2.png)

#### 3
![main2](https://destan19.github.io/assets/img/oaf/oaf3.png)


#### 4
![main2](https://destan19.github.io/assets/img/oaf/oaf4.png)


## 编译说明
1. 下载OpenWrt源码，并完成编译
> git clone https://github.com/coolsnowwolf/lede.git  
> 或 https://github.com/openwrt/openwrt.git  （18.06）
2. 下载应用过滤源码放到OpenWrt的package 目录
> cd package  
git clone https://github.com/destan19/OpenAppFilter.git  
cd -
3. make menuconfig, 在luci app中选上luci oaf app模块并保存 
4. make V=s 编译出带应用过滤功能的OpenWrt固件   
也可以将源码路径加入到feeds配置中  

## 使用说明
1. 应用过滤与加速模块、广告过滤、mwan等涉及到nf_conntrack mark的模块有冲突，需要关闭冲突模块才能生效。  
2. 应用过滤包含了内核模块，内核版本号和宏配置都会影响插件安装，建议直接编译进固件。  
3. 如果你的固件集成了应用过滤插件，并进行二次发布，请备注应用过滤仓库地址，谢谢！  

## 技术交流QQ群 (2000人)
943396288  
点击链接加入群聊【OpenWrt交流群(OAF)】：https://jq.qq.com/?_wv=1027&k=YQaeDqTY
