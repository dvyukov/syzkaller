// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/vm/vmimpl"
)

const (
	hostAddr = "10.0.2.10"
)

func init() {
	vmimpl.Register("qemu", ctor)
}

type Config struct {
	Count       int    `json:"count"`        // number of VMs to use
	Qemu        string `json:"qemu"`         // qemu binary name (qemu-system-arch by default)
	QemuArgs    string `json:"qemu_args"`    // additional command line arguments for qemu binary
	Kernel      string `json:"kernel"`       // kernel for injected boot (e.g. arch/x86/boot/bzImage)
	Cmdline     string `json:"cmdline"`      // kernel command line (can only be specified with kernel)
	Initrd      string `json:"initrd"`       // linux initial ramdisk. (optional)
	ImageDevice string `json:"image_device"` // qemu image device (hda by default)
	CPU         int    `json:"cpu"`          // number of VM CPUs
	Mem         int    `json:"mem"`          // amount of VM memory in MBs
}

type Pool struct {
	env        *vmimpl.Env
	cfg        *Config
	archConfig *archConfig
}

type instance struct {
	cfg        *Config
	archConfig *archConfig
	image      string
	debug      bool
	workdir    string
	sshkey     string
	sshuser    string
	fuzzerBin string
	port       int
	rpipe      io.ReadCloser
	wpipe      io.WriteCloser
	qemu       *exec.Cmd
	waiterC    chan error
	merger     *vmimpl.OutputMerger
}

type archConfig struct {
	Qemu      string
	QemuArgs  string
	TargetDir string
	CmdLine   []string
}

var archConfigs = map[string]*archConfig{
	"linux/amd64": {
		Qemu:      "qemu-system-x86_64",
		QemuArgs:  "-enable-kvm",
		TargetDir: "/",
		CmdLine: append(linuxCmdline,
			"kvm-intel.nested=1",
			"kvm-intel.unrestricted_guest=1",
			"kvm-intel.vmm_exclusive=1",
			"kvm-intel.fasteoi=1",
			"kvm-intel.ept=1",
			"kvm-intel.flexpriority=1",
			"kvm-intel.vpid=1",
			"kvm-intel.emulate_invalid_guest_state=1",
			"kvm-intel.eptad=1",
			"kvm-intel.enable_shadow_vmcs=1",
			"kvm-intel.pml=1",
			"kvm-intel.enable_apicv=1",
		),
	},
	"linux/386": {
		Qemu:      "qemu-system-i386",
		TargetDir: "/",
		CmdLine:   linuxCmdline,
	},
	"linux/arm64": {
		Qemu:      "qemu-system-aarch64",
		QemuArgs:  "-machine virt -cpu cortex-a57",
		TargetDir: "/",
		CmdLine:   linuxCmdline,
	},
	"linux/arm": {
		Qemu:      "qemu-system-arm",
		TargetDir: "/",
		CmdLine:   linuxCmdline,
	},
	"linux/ppc64le": {
		Qemu:      "qemu-system-ppc64",
		TargetDir: "/",
		CmdLine:   linuxCmdline,
	},
	"freebsd/amd64": {
		Qemu:      "qemu-system-x86_64",
		TargetDir: "/",
		QemuArgs:  "-enable-kvm",
	},
	"netbsd/amd64": {
		Qemu:      "qemu-system-x86_64",
		TargetDir: "/",
		QemuArgs:  "-enable-kvm",
	},
	"fuchsia/amd64": {
		Qemu:      "qemu-system-x86_64",
		QemuArgs:  "-enable-kvm -machine q35 -cpu host",
		TargetDir: "/tmp",
		CmdLine: []string{
			"kernel.serial=legacy",
			"kernel.halt-on-panic=true",
		},
	},
	"akaros/amd64": {
		Qemu:      "qemu-system-x86_64",
		QemuArgs:  "-enable-kvm -cpu host",
		TargetDir: "/",
	},
}

var linuxCmdline = []string{
	"console=ttyS0",
	"earlyprintk=serial",
	"oops=panic",
	"nmi_watchdog=panic",
	"panic_on_warn=1",
	"panic=86400",
	"ftrace_dump_on_oops=orig_cpu",
	"rodata=n",
	"vsyscall=native",
	"net.ifnames=0",
	"biosdevname=0",
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	archConfig := archConfigs[env.OS+"/"+env.Arch]
	cfg := &Config{
		Count:       1,
		ImageDevice: "hda",
		Qemu:        archConfig.Qemu,
		QemuArgs:    archConfig.QemuArgs,
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse qemu vm config: %v", err)
	}
	if cfg.Count < 1 || cfg.Count > 1000 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 1000]", cfg.Count)
	}
	if env.Debug {
		cfg.Count = 1
	}
	if _, err := exec.LookPath(cfg.Qemu); err != nil {
		return nil, err
	}
	if env.Image == "9p" {
		if env.OS != "linux" {
			return nil, fmt.Errorf("9p image is supported for linux only")
		}
		if cfg.Kernel == "" {
			return nil, fmt.Errorf("9p image requires kernel")
		}
	} else {
		if !osutil.IsExist(env.Image) {
			return nil, fmt.Errorf("image file '%v' does not exist", env.Image)
		}
	}
	if cfg.CPU <= 0 || cfg.CPU > 1024 {
		return nil, fmt.Errorf("bad qemu cpu: %v, want [1-1024]", cfg.CPU)
	}
	if cfg.Mem < 128 || cfg.Mem > 1048576 {
		return nil, fmt.Errorf("bad qemu mem: %v, want [128-1048576]", cfg.Mem)
	}
	cfg.Kernel = osutil.Abs(cfg.Kernel)
	cfg.Initrd = osutil.Abs(cfg.Initrd)
	pool := &Pool{
		cfg:        cfg,
		env:        env,
		archConfig: archConfig,
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	sshkey := pool.env.SSHKey
	sshuser := pool.env.SSHUser
	if pool.env.Image == "9p" {
		sshkey = filepath.Join(workdir, "key")
		sshuser = "root"
		if _, err := osutil.RunCmd(10*time.Minute, "", "ssh-keygen", "-t", "rsa", "-b", "2048",
			"-N", "", "-C", "", "-f", sshkey); err != nil {
			return nil, err
		}
		initFile := filepath.Join(workdir, "init.sh")
		if err := osutil.WriteExecFile(initFile, []byte(strings.Replace(initScript, "{{KEY}}", sshkey, -1))); err != nil {
			return nil, fmt.Errorf("failed to create init file: %v", err)
		}
	}

	for i := 0; ; i++ {
		inst, err := pool.ctor(workdir, sshkey, sshuser, index)
		if err == nil {
			return inst, nil
		}
		// Older qemu prints "could", newer -- "Could".
		if i < 1000 && strings.Contains(err.Error(), "ould not set up host forwarding rule") {
			continue
		}
		return nil, err
	}
}

func (pool *Pool) ctor(workdir, sshkey, sshuser string, index int) (vmimpl.Instance, error) {
	inst := &instance{
		cfg:        pool.cfg,
		archConfig: pool.archConfig,
		image:      pool.env.Image,
		debug:      pool.env.Debug,
		workdir:    workdir,
		sshkey:     sshkey,
		sshuser:    sshuser,
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()

	var err error
	inst.rpipe, inst.wpipe, err = osutil.LongPipe()
	if err != nil {
		return nil, err
	}

	if err := inst.Boot(); err != nil {
		return nil, err
	}

	closeInst = nil
	return inst, nil
}

func (inst *instance) Close() {
	if inst.qemu != nil {
		inst.qemu.Process.Kill()
		err := <-inst.waiterC
		inst.waiterC <- err // repost it for waiting goroutines
	}
	if inst.merger != nil {
		inst.merger.Wait()
	}
	if inst.rpipe != nil {
		inst.rpipe.Close()
	}
	if inst.wpipe != nil {
		inst.wpipe.Close()
	}
}

func (inst *instance) Boot() error {
	inst.port = vmimpl.UnusedTCPPort()
	args := []string{
		"-m", strconv.Itoa(inst.cfg.Mem),
		"-smp", strconv.Itoa(inst.cfg.CPU),
		"-net", "nic",
		"-net", fmt.Sprintf("user,host=%v,hostfwd=tcp::%v-:22", hostAddr, inst.port),
		"-display", "none",
		"-serial", "stdio",
		"-no-reboot",
	}
	args = append(args, strings.Split(inst.cfg.QemuArgs, " ")...)
	if inst.image == "9p" {
		args = append(args,
			"-fsdev", "local,id=fsdev0,path=/,security_model=none,readonly",
			"-device", "virtio-9p-pci,fsdev=fsdev0,mount_tag=/dev/root",
		)
	} else {
		/*
		args = append(args,
			"-"+inst.cfg.ImageDevice, inst.image,
			"-snapshot",
		)
		*/
	}
	if inst.cfg.Initrd != "" {
		args = append(args,
			"-initrd", inst.cfg.Initrd,
		)
	}
	if inst.cfg.Kernel != "" {
		cmdline := append([]string{}, inst.archConfig.CmdLine...)
		if inst.image == "9p" {
			cmdline = append(cmdline,
				"root=/dev/root",
				"rootfstype=9p",
				"rootflags=trans=virtio,version=9p2000.L,cache=loose",
				"init="+filepath.Join(inst.workdir, "init.sh"),
			)
		} else {
			cmdline = append(cmdline, "root=/dev/sda")
		}
		cmdline = append(cmdline, inst.cfg.Cmdline)
		args = append(args,
			"-kernel", inst.cfg.Kernel,
			"-append", strings.Join(cmdline, " "),
		)
	}
	if inst.debug {
		log.Logf(0, "running command: %v %#v", inst.cfg.Qemu, args)
	}
	qemu := osutil.Command(inst.cfg.Qemu, args...)
	qemu.Stdout = inst.wpipe
	qemu.Stderr = inst.wpipe
	if err := qemu.Start(); err != nil {
		return fmt.Errorf("failed to start %v %+v: %v", inst.cfg.Qemu, args, err)
	}
	inst.wpipe.Close()
	inst.wpipe = nil
	inst.qemu = qemu
	// Qemu has started.

	// Start output merger.
	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	inst.merger = vmimpl.NewOutputMerger(tee)
	inst.merger.Add("qemu", inst.rpipe)
	inst.rpipe = nil

	var bootOutput []byte
	bootOutputStop := make(chan bool)
	go func() {
		for {
			select {
			case out := <-inst.merger.Output:
				bootOutput = append(bootOutput, out...)
			case <-bootOutputStop:
				close(bootOutputStop)
				return
			}
		}
	}()

	// Wait for the qemu asynchronously.
	inst.waiterC = make(chan error, 1)
	go func() {
		err := qemu.Wait()
		inst.waiterC <- err
	}()

	// Wait for ssh server to come up.
	time.Sleep(5 * time.Second)
	start := time.Now()
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%v", inst.port), 1*time.Second)
		if err == nil {
			c.SetDeadline(time.Now().Add(1 * time.Second))
			var tmp [1]byte
			n, err := c.Read(tmp[:])
			c.Close()
			if err == nil && n > 0 {
				break // ssh is up and responding
			}
			time.Sleep(3 * time.Second)
		}
		select {
		case err := <-inst.waiterC:
			inst.waiterC <- err     // repost it for Close
			time.Sleep(time.Second) // wait for any pending output
			bootOutputStop <- true
			<-bootOutputStop
			return vmimpl.BootError{Title: "qemu stopped", Output: bootOutput}
		default:
		}
		if time.Since(start) > 10*time.Minute {
			bootOutputStop <- true
			<-bootOutputStop
			return vmimpl.BootError{Title: "ssh server did not start", Output: bootOutput}
		}
	}
	bootOutputStop <- true
	return nil
}

func (inst *instance) Forward(port int) (string, error) {
	//return fmt.Sprintf("%v:%v", hostAddr, port), nil
	return fmt.Sprintf("127.0.0.1:%v", port), nil
}

func (inst *instance) targetDir() string {
	if inst.image == "9p" {
		return "/tmp"
	}
	return inst.archConfig.TargetDir
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	base := filepath.Base(hostSrc)
	if base == "syz-fuzzer" {
		inst.fuzzerBin = base
		return hostSrc, nil
	}
	vmDst := filepath.Join(inst.targetDir(), base)
	args := append(inst.sshArgs("-P"), hostSrc, inst.sshuser+"@localhost:"+vmDst)
	cmd := osutil.Command("scp", args...)
	if inst.debug {
		log.Logf(0, "running command: scp %#v", args)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan bool)
	go func() {
		select {
		case <-time.After(3 * time.Minute):
			cmd.Process.Kill()
		case <-done:
		}
	}()
	err := cmd.Wait()
	close(done)
	if err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	<-chan []byte, <-chan error, error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}
	inst.merger.Add("ssh", rpipe)

	/*
	args := append(inst.sshArgs("-p"), inst.sshuser+"@localhost", "cd "+inst.targetDir()+" && "+command)
	if inst.debug {
		log.Logf(0, "running command: ssh %#v", args)
	}
	cmd := osutil.Command("ssh", args...)
	*/

	args := strings.Split(command, " ")
	for i, arg := range args {
		if strings.HasPrefix(arg, "-executor=") {
			args[i] = "-executor=" + "/usr/bin/ssh " + strings.Join(inst.sshArgs("-p"), " ") +
				" " + inst.sshuser+"@localhost " + arg[len("-executor="):]
			break
		}
	}
	if inst.debug {
		log.Logf(0, "running command: %#v", args)
	}
	cmd := osutil.Command(args[0], args[1:]...)
	cmd.Dir = inst.workdir
	
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		wpipe.Close()
		return nil, nil, err
	}
	wpipe.Close()
	errc := make(chan error, 1)
	signal := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}

	go func() {
		select {
		case <-time.After(timeout):
			signal(vmimpl.ErrTimeout)
		case <-stop:
			signal(vmimpl.ErrTimeout)
		case err := <-inst.merger.Err:
			cmd.Process.Kill()
			if cmdErr := cmd.Wait(); cmdErr == nil {
				// If the command exited successfully, we got EOF error from merger.
				// But in this case no error has happened and the EOF is expected.
				err = nil
			}
			signal(err)
			return
		}
		cmd.Process.Kill()
		cmd.Wait()
	}()
	return inst.merger.Output, errc, nil
}

func (inst *instance) Diagnose() bool {
	return false
}

func (inst *instance) sshArgs(portArg string) []string {
	args := []string{
		portArg, strconv.Itoa(inst.port),
		"-F", "/dev/null",
		"-o", "ConnectionAttempts=10",
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "LogLevel=error",
	}
	if inst.sshkey != "" {
		args = append(args, "-i", inst.sshkey)
	}
	if inst.debug {
		args = append(args, "-v")
	}
	return args
}

// nolint: lll
const initScript = `#! /bin/bash
set -eux
mount -t proc none /proc
mount -t sysfs none /sys
mount -t debugfs nodev /sys/kernel/debug/
mount -t tmpfs none /tmp
mount -t tmpfs none /var
mount -t tmpfs none /run
mount -t tmpfs none /etc
mount -t tmpfs none /root
touch /etc/fstab
mkdir /etc/network
mkdir /run/network
printf 'auto lo\niface lo inet loopback\n\n' >> /etc/network/interfaces
printf 'auto eth0\niface eth0 inet static\naddress 10.0.2.15\nnetmask 255.255.255.0\nnetwork 10.0.2.0\ngateway 10.0.2.1\nbroadcast 10.0.2.255\n\n' >> /etc/network/interfaces
printf 'auto eth0\niface eth0 inet6 static\naddress fe80::5054:ff:fe12:3456/64\ngateway 2000:da8:203:612:0:3:0:1\n\n' >> /etc/network/interfaces
mkdir -p /etc/network/if-pre-up.d
mkdir -p /etc/network/if-up.d
ifup lo
ifup eth0 || true
echo "root::0:0:root:/root:/bin/bash" > /etc/passwd
mkdir -p /etc/ssh
cp {{KEY}}.pub /root/
chmod 0700 /root
chmod 0600 /root/key.pub
mkdir -p /var/run/sshd/
chmod 700 /var/run/sshd
groupadd -g 33 sshd
useradd -u 33 -g 33 -c sshd -d / sshd
cat > /etc/ssh/sshd_config <<EOF
          Port 22
          Protocol 2
          UsePrivilegeSeparation no
          HostKey {{KEY}}
          PermitRootLogin yes
          AuthenticationMethods publickey
          ChallengeResponseAuthentication no
          AuthorizedKeysFile /root/key.pub
          IgnoreUserKnownHosts yes
          AllowUsers root
          LogLevel INFO
          TCPKeepAlive yes
          RSAAuthentication yes
          PubkeyAuthentication yes
EOF
/usr/sbin/sshd -e -D
/sbin/halt -f
`
