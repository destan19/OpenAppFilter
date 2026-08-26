OBJS:=fwx_user.o fwx_netlink.o fwx_ubus.o fwx_stat.o fwx_config.o fwx_feature.o fwx_feature_online.o fwx_custom_feature.o fwx_utils.o main.o  fwx_app_filter.o fwx_mac_filter.o fwx_record.o fwx_common.o fwx_system.o fwx_network.o fwx_firewall.o fwx_wireless.o check_main.o fwx_uci.o
EXEC:=oafd
all: $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) $(LIBS)
clean:
	rm $(EXEC) *.o
