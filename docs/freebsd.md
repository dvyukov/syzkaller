# FreeBSD

https://wiki.qemu.org/Hosts/BSD

in /boot/loader.conf add:

autoboot_delay="-1"
console="comconsole"

# cat /etc/rc.conf
sshd_enable="YES"
ifconfig_em0="inet 10.0.0.1 netmask 255.255.255.0"




qemu-system-x86_64 -m 2048 -hda ~/Downloads/FreeBSD-11.0-RELEASE-amd64.qcow2 -enable-kvm -netdev user,id=mynet0,host=10.0.2.10,hostfwd=tcp::10022-:22 -device e1000,netdev=mynet0 -nographic

-net user,host=10.0.2.10,hostfwd=tcp::10022-:22 -net nic

-netdev user,id=mynet0,host=10.0.2.10,hostfwd=tcp::10022-:22 -device e1000,netdev=mynet0

/etc/ssh/ssh_host_rsa_key



qemu-system-x86_64 -hda /usr/local/google/home/dvyukov/bin/wheezy.img -net user,host=10.0.2.10,hostfwd=tcp::10022-:22 -net nic -nographic -kernel arch/x86/boot/bzImage -append "kvm-intel.nested=1 kvm-intel.unrestricted_guest=1 kvm-intel.ept=1 kvm-intel.flexpriority=1 kvm-intel.vpid=1 kvm-intel.emulate_invalid_guest_state=1 kvm-intel.eptad=1 kvm-intel.enable_shadow_vmcs=1 kvm-intel.pml=1 kvm-intel.enable_apicv=1 console=ttyS0 root=/dev/sda earlyprintk=serial slub_debug=UZ vsyscall=native rodata=n oops=panic panic_on_warn=1 panic=86400" -enable-kvm -pidfile vm_pid -m 2G -smp 4 -cpu host -usb -usbdevice mouse -usbdevice tablet -soundhw all 2>&1 | tee vm_log


ssh -i ~/Downloads/freebsd_id_rsa -o IdentitiesOnly=yes -p 10022 root@127.0.0.1
scp -i ~/Downloads/freebsd_id_rsa -o IdentitiesOnly=yes -P 10022 executor/* root@127.0.0.1:/root/executor/
scp -i ~/Downloads/freebsd_id_rsa -o IdentitiesOnly=yes -P 10022 root@127.0.0.1:/root/syz-executor bin/freebsd_amd64/

root@:~ # cat /etc/ssh/sshd_config

Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
SyslogFacility AUTH
LogLevel INFO
AuthenticationMethods publickey password
PermitRootLogin yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2
PasswordAuthentication yes
PermitEmptyPasswords yes
Subsystem       sftp    /usr/libexec/sftp-server

