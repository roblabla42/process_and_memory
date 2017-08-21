GET_PID_INFO_SOURCES = get_pid_info.c
TEST_PID_INFO_OBJS = test_pid_info.c

LINUX_SRC ?= /usr/src/linux

all: test-pid-info setup-kernel

setup-kernel: clean
	mkdir -p $(LINUX_SRC)/get_pid_info
	cp $(GET_PID_INFO_SOURCES) $(LINUX_SRC)/get_pid_info/get_pid_info.c
	echo "obj-y := get_pid_info.o" > $(LINUX_SRC)/get_pid_info/Makefile
	echo "350	common	get_pid_info			sys_get_pid_info" >> $(LINUX_SRC)/arch/x86/entry/syscalls/syscall_64.tbl
	sed -i "/^core-y\s*+=/ s/$$/ get_pid_info\//" $(LINUX_SRC)/Makefile
	#zcat /proc/config.gz > $(LINUX_SRC)/.config
	make -j8 -C $(LINUX_SRC)
	cp $(LINUX_SRC)/arch/x86_64/boot/bzImage /boot/vmlinuz-process_and_memory
	cp $(LINUX_SRC)/System.map /boot/System.map-process_and_memory
	reboot

test-pid-info: $(TEST_PID_INFO_OBJS)
	$(CC) -o test-pid-info $(TEST_PID_INFO_OBJS)

clean:
	sed -i "s/ get_pid_info\///g" $(LINUX_SRC)/Makefile
	sed -i '/get_pid_info/ d' $(LINUX_SRC)/arch/x86/entry/syscalls/syscall_64.tbl
	rm -rf $(LINUX_SRC)/get_pid_info
	rm -f test-pid-info.o

fclean: clean
	rm test-pid-info
	make -C $(LINUX_SRC) mrproper

re: fclean all

.PHONY: all setup-kernel-module clean fclean re
