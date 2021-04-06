
### 插件和特征库发布地址

https://destan19.github.io/
### OpenAppFilter功能简介

OpenAppFilter模块基于数据流深度识别技术，实现对单个app进行管控的功能，并支持上网记录统计

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
> 或 https://github.com/openwrt/openwrt.git  
2. 下载应用过滤源码放到OpenWrt的package 目录
> cd package  
git clone https://github.com/destan19/OpenAppFilter.git  
cd -
3. make menuconfig, 在luci app中选上luci oaf app模块并保存 
4. make V=s 编译出带应用过滤功能的OpenWrt固件 

## 使用说明
应用过滤和加速模块、广告过滤等模块有冲突,请关闭后使用

## 技术交流QQ群 
943396288  
点击链接加入群聊【OpenWrt交流群(OAF)】：https://jq.qq.com/?_wv=1027&k=YQaeDqTY

