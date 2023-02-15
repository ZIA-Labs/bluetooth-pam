
ROOTDISK := /dev/disk3s1

mac:
	gcc -dynamiclib -fPIC -fno-stack-protector src/zia_auth.c -o zia_auth.so -lpam -lcurl

macinstall:
	sudo mkdir -p /opt/zialabs/usr/lib/pam
	sudo cp zia_auth.so /opt/zialabs/usr/lib/pam
#	sudo mount -o nobrowse -t apfs $(ROOTDISK) ~/mount
#	sudo cp zia_auth.so ~/mount/usr/lib/pam
#	$(shell sudo bless --mount $HOME/mount/System/Library/CoreServices/ --setBoot --create-snapshot)
#	sudo umount ~/mount
