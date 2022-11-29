## OAF(Open App Filter)  
OAF is a parent management plug-in based on OpenWrt, which supports app filtering for games, videos, chats, downloads, etc.  

### How to compile OAF  
1. Prepare OpenWrt source or SDK and compile successfully   
- general steps  
```
   git clone https://github.com/openwrt/openwrt
   cd openwrt
   ./script update -a
   ./script install -a
   make defconfig
   make V=s
```   
2. Download OAF source code  
git clone https://github.com/destan19/OpenAppFilter.git package/OpenAppFilter    
3. Open the compile configuration   
```
     echo luci-app-oaf >>.config  
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
### How to install OAF  
If you can't compile it yourself, you can install it directly into the released OpenWrt version  
1. Install an officially released version of openwrt  
Note that it must be the official release version,may cause failure if other versions are used, because OAF depend on the kernel version.  
It is best to download through the following official address  
https://downloads.openwrt.org/releases   
2. Download OAF zip file  
Find the corresponding OAF zip file on the release page and download it, note that the plug-in version and the system version must be consistent.  
3. Install OAF ipks  
Unzip thie OAF package and then install ipks in order  
- kmod-oaf  
- appfilter   
- luci-compat(if the luci version is 2.0, openwrt 19.07+)   
- luci-app-oaf    
- luci-i18n-oaf-zh-cn(Chinese Language Pack, optional)  

### Notice
If there is no version you need, you can wait for a while to check, more models will be released later, or learn to compile it yourself.  
