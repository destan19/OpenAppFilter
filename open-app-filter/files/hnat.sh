. /usr/share/libubox/jshn.sh
. /lib/functions.sh

disable_hnat=`uci get appfilter.global.disable_hnat`

if [ x"1" != x"$disable_hnat" ];then
    return
fi

# mt798x                                          
test -d /sys/kernel/debug/hnat  && {              
    echo 0 >/sys/kernel/debug/hnat/hook_toggle    
}                                                                                 
# qca ecm                                                                         
test -d /sys/kernel/debug/ecm/ && {                                               
    echo "1000000" > /sys/kernel/debug/ecm/ecm_classifier_default/accel_delay_pkts
}                                      

# turbo acc
test -f /etc/config/turboacc && {
    uci -q set "turboacc.config.fastpath_fo_hw"="0"
    uci -q set "turboacc.config.fastpath_fc_ipv6"="0"
    uci -q set "turboacc.config.fastpath"="none"
    uci -q set "turboacc.config.fullcone"="0"
    /etc/init.d/turboacc restart &
}

uci -q set "firewall.@defaults[0].flow_offloading_hw"='0'
uci -q set "firewall.@defaults[0].flow_offloading"='0'
uci -q set "firewall.@defaults[0].fullcone"='0'

fw3 reload &

