// Copyright 2020 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package cisco_iol

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/charmbracelet/log"
	"github.com/scrapli/scrapligo/driver/options"
	"github.com/scrapli/scrapligo/platform"
	"github.com/scrapli/scrapligo/transport"
	clabconstants "github.com/srl-labs/containerlab/constants"
	clabexec "github.com/srl-labs/containerlab/exec"
	clablinks "github.com/srl-labs/containerlab/links"
	clabnodes "github.com/srl-labs/containerlab/nodes"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	clabtypes "github.com/srl-labs/containerlab/types"
	clabutils "github.com/srl-labs/containerlab/utils"
)

const (
	typeIOL = "iol"
	typeL2  = "l2"

	iol_workdir = "/iol"

	generateable     = true
	generateIfFormat = "eth%d"

	scrapliPlatformName = "cisco_ios"
	NapalmPlatformName  = "ios"
)

var (
	kindNames          = []string{"cisco_iol"}
	defaultCredentials = clabnodes.NewCredentials("admin", "admin")

	//go:embed iol.cfg.tmpl
	cfgTemplate string

	// IntfRegexp with named capture groups for extracting slot and port.
	CapturingIntfRegexp = regexp.MustCompile(`(?:e|Ethernet)\s?(?P<slot>\d+)/(?P<port>\d+)$`)
	// ethX naming is the "raw" or "default" interface naming.
	DefaultIntfRegexp = regexp.MustCompile(`eth[1-9]\d*$`)
	// Match on the management interface.
	MgmtIntfRegexp = regexp.MustCompile(`(eth0|e0/0|Ethernet0/0)$`)
	// Matches on any allowed/legal interface name.
	AllowedIntfRegexp = regexp.MustCompile(`(e|Ethernet)((0/[123])|([1-9]/[0-3]))$|eth[1-9]\d*$`)
	IntfHelpMsg       = "Interfaces should follow Ethernet<slot>/<port> or e<slot>/<port> naming convention, where <slot> is a number from 0-9 and <port> is a number from 0-3. You can also use ethX-based interface naming."

	validTypes = []string{typeIOL, typeL2}
)

// Register registers the node in the NodeRegistry.
func Register(r *clabnodes.NodeRegistry) {
	generateNodeAttributes := clabnodes.NewGenerateNodeAttributes(generateable, generateIfFormat)
	platformAttrs := &clabnodes.PlatformAttrs{
		ScrapliPlatformName: scrapliPlatformName,
		NapalmPlatformName:  NapalmPlatformName,
	}

	nrea := clabnodes.NewNodeRegistryEntryAttributes(
		defaultCredentials,
		generateNodeAttributes,
		platformAttrs,
	)

	r.Register(kindNames, func() clabnodes.Node {
		return new(iol)
	}, nrea)
}

type iol struct {
	clabnodes.DefaultNode

	isL2Node          bool
	Pid               string
	nvramFile         string
	hostNvram         string
	hostVlanDat       string
	partialStartupCfg string
	bootCfg           string
	interfaces        []IOLInterface
	firstBoot         bool
	// bootCfgWritten is set when PreDeploy rendered the complete boot config (NTG-180).
	bootCfgWritten bool
	// parkedEndpoints are the links apply parked before recreating this node (NTG-263).
	parkedEndpoints []clablinks.Endpoint
	// created is set when this run creates the container: its entrypoint starts iouyap (NTG-333).
	created                      bool
	fixedSlotsN, runningSlotsN   int
	fixedSlotsOK, runningSlotsOK bool
	runningSlotsErr              error
}

func (n *iol) Init(cfg *clabtypes.NodeConfig, opts ...clabnodes.NodeOption) error {
	// Init DefaultNode
	n.DefaultNode = *clabnodes.NewDefaultNode(n)
	n.firstBoot = false

	n.Cfg = cfg
	for _, o := range opts {
		o(n)
	}

	nodeType := strings.ToLower(n.Cfg.NodeType)

	pid, err := iolPid(n.Cfg.Env, n.Cfg.MgmtIPv4Address, n.Cfg.Index)
	if err != nil {
		return fmt.Errorf("node %s: %w", n.Cfg.ShortName, err)
	}
	n.Pid = strconv.Itoa(pid)

	// After the merge: IOL_PID must match the NVRAM file name and NETMAP.
	n.Cfg.Env = clabutils.MergeStringMaps(n.Cfg.Env, map[string]string{"IOL_PID": n.Pid})

	// check if user submitted node type is valid
	switch nodeType {
	case "", typeIOL:
		n.isL2Node = false
	case typeL2:
		n.isL2Node = true
	default:
		return fmt.Errorf("invalid node type '%s'. Valid types are: %s",
			n.Cfg.NodeType, strings.Join(validTypes, ", "))
	}

	n.nvramFile = fmt.Sprint("nvram_", fmt.Sprintf("%05s", n.Pid))
	// NTG-231: one host file per node, whatever the PID, so the saved config follows the node.
	n.hostNvram = path.Join(n.Cfg.LabDir, "nvram")
	// NTG-233: VLANs and the VTP state live in vlan.dat-<PID>, not in NVRAM. L3 never writes it.
	n.hostVlanDat = path.Join(n.Cfg.LabDir, "vlan.dat")

	n.Cfg.Binds = append(n.Cfg.Binds,
		// mount nvram so that config persists
		fmt.Sprint(n.hostNvram, ":", path.Join(iol_workdir, n.nvramFile)),
		fmt.Sprint(n.hostVlanDat, ":", path.Join(iol_workdir, fmt.Sprintf("vlan.dat-%05s", n.Pid))),

		// mount launch config
		fmt.Sprint(filepath.Join(n.Cfg.LabDir, "boot_config.txt"), ":/iol/config.txt"),

		// mount IOYAP and NETMAP for interface mapping
		fmt.Sprint(filepath.Join(n.Cfg.LabDir, "iouyap.ini"), ":/iol/iouyap.ini"),
		fmt.Sprint(filepath.Join(n.Cfg.LabDir, "NETMAP"), ":/iol/NETMAP"),
	)

	return nil
}

func (n *iol) PreDeploy(ctx context.Context, params *clabnodes.PreDeployParams) error {
	clabutils.CreateDirectory(n.Cfg.LabDir, clabconstants.PermissionsOpen)

	_, err := n.LoadOrGenerateCertificate(params.Cert, params.TopologyName)
	if err != nil {
		return err
	}

	n.created = true
	return n.CreateIOLFiles(ctx)
}

func (n *iol) PostDeploy(ctx context.Context, _ *clabnodes.PostDeployParams) error {
	log.Infof("Running postdeploy actions for Cisco IOL '%s' node", n.Cfg.ShortName)

	// Disable TX checksum offload on the host NS veth for the mgmt interface.
	var peerIfIndex int
	err := n.ExecFunction(ctx, clabutils.VethPeerIndex("eth0", &peerIfIndex))
	if err != nil {
		log.Warn("Failed to get veth peer index for IOL mgmt interface",
			"node", n.Cfg.ShortName,
			"error", err)
		return nil
	}

	if err := clabutils.DisableTxOffloadByIndex(peerIfIndex); err != nil {
		log.Warn("Failed to disable TX checksum offload on IOL mgmt host veth",
			"node", n.Cfg.ShortName,
			"error", err)
	}

	if err := n.postDeployBootConfig(ctx); err != nil {
		return fmt.Errorf("failed to generate boot config: %w", err)
	}

	return n.updateMgmtAfterBoot(ctx)
}

// updateMgmtAfterBoot types the mgmt address into a rebooted node (its NVRAM config may hold an old one).
// A console node has no mgmt address in its config, and typing into its stdin would bypass the grader's
// console lock and `wr` the student's running config (NTG-253 S6).
func (n *iol) updateMgmtAfterBoot(ctx context.Context) error {
	if n.firstBoot || n.consoleMode() {
		return nil
	}
	// iol has a 5sec boot delay, wait a few extra secs for the console
	time.Sleep(10 * time.Second)
	return n.UpdateMgmtIntf(ctx)
}

func (n *iol) CreateIOLFiles(ctx context.Context) error {
	if err := n.adoptLegacyNvram(); err != nil {
		return err
	}
	// If NVRAM already exists, don't need to create
	// otherwise saved configs in NVRAM are overwritten.
	if !clabutils.FileExists(n.hostNvram) {
		if err := clabutils.CreateFile(n.hostNvram, ""); err != nil {
			return err
		}
	}
	// NTG-207: still clab's placeholder (one byte, "\n"), so IOL never ran on it (a node recreated
	// right after its first create, when the next apply adds its links). Booting from the boot
	// config is a first boot; the 10 s wait and mgmt re-push in PostDeploy ran per node.
	n.firstBoot = !nvramWritten(n.hostNvram)
	// Empty, not CreateFile's "\n": IOS logs %SW_VLAN-4-IFS_FAILURE at boot on a one-byte file.
	if !clabutils.FileExists(n.hostVlanDat) {
		if err := os.WriteFile(n.hostVlanDat, nil, 0o666); err != nil {
			return err
		}
	}

	// create these files so the bind monut doesn't automatically
	// make folders.
	clabutils.CreateFile(path.Join(n.Cfg.LabDir, "boot_config.txt"), "")

	if s := n.fixedSlots(ctx); s > 0 && n.Cfg.Env[envNumSlots] == "" {
		n.Cfg.Env = clabutils.MergeStringMaps(n.Cfg.Env, map[string]string{envNumSlots: strconv.Itoa(s)})
	}

	if err := n.GenInterfaceConfig(ctx); err != nil {
		return err
	}

	// NTG-180: IOL reads /iol/config.txt a few seconds after the container starts, while
	// PostDeploy runs after the start and one node at a time, so a later node could read it empty
	// or cut off. With a pinned mgmt address everything the config needs is known now (the mgmt
	// network exists before nodes are created), so write it before the container starts.
	if n.Cfg.MgmtIPv4Address == "" {
		return nil
	}
	if err := n.fillMgmtNetFromRuntime(); err != nil {
		return err
	}
	if err := n.GenBootConfig(ctx); err != nil {
		return err
	}
	n.bootCfgWritten = true

	return nil
}

// fillMgmtNetFromRuntime sets the mgmt gateway and prefix length, which are otherwise only read
// from the running container, from the runtime's mgmt network (as cEOS does for its config).
func (n *iol) fillMgmtNetFromRuntime() error {
	mgmt := n.Runtime.Mgmt()
	if n.Cfg.MgmtIPv4Gateway == "" {
		n.Cfg.MgmtIPv4Gateway = mgmt.IPv4Gw
	}
	if n.Cfg.MgmtIPv4PrefixLength == 0 && mgmt.IPv4Subnet != "" {
		_, subnet, err := net.ParseCIDR(mgmt.IPv4Subnet)
		if err != nil {
			return fmt.Errorf("mgmt ipv4 subnet %q: %w", mgmt.IPv4Subnet, err)
		}
		n.Cfg.MgmtIPv4PrefixLength, _ = subnet.Mask.Size()
	}
	if n.Cfg.MgmtIPv6Address != "" {
		if n.Cfg.MgmtIPv6Gateway == "" {
			n.Cfg.MgmtIPv6Gateway = mgmt.IPv6Gw
		}
		if n.Cfg.MgmtIPv6PrefixLength == 0 && mgmt.IPv6Subnet != "" {
			_, subnet, err := net.ParseCIDR(mgmt.IPv6Subnet)
			if err != nil {
				return fmt.Errorf("mgmt ipv6 subnet %q: %w", mgmt.IPv6Subnet, err)
			}
			n.Cfg.MgmtIPv6PrefixLength, _ = subnet.Mask.Size()
		}
	}
	return nil
}

// postDeployBootConfig writes the boot config only when nothing complete is there yet. Rewriting it
// while IOL boots can be read half-written, and a restart (no PreDeploy) has no data interfaces to
// render, so an existing config is kept as it is (NTG-180).
func (n *iol) postDeployBootConfig(ctx context.Context) error {
	if n.bootCfgWritten {
		return nil
	}
	existing, err := os.ReadFile(path.Join(n.Cfg.LabDir, "boot_config.txt"))
	if err == nil && strings.TrimSpace(string(existing)) != "" {
		return nil
	}
	return n.GenBootConfig(ctx)
}

// ParkEndpoints remembers the links before parking releases them from the node (NTG-263).
func (n *iol) ParkEndpoints(ctx context.Context) error {
	n.rememberParkedEndpoints()
	return n.DefaultNode.ParkEndpoints(ctx)
}

// NTG-263: parking releases a node's links, and the recreated IOL writes NETMAP before they come
// back. IOL and iouyap read NETMAP only at boot, so it must list the parked links too.
func (n *iol) rememberParkedEndpoints() {
	n.parkedEndpoints = append([]clablinks.Endpoint(nil), n.Endpoints...)
}

// interfaceEndpoints is every link the booting node will have: parked ones and current ones.
func (n *iol) interfaceEndpoints() []clablinks.Endpoint {
	seen := map[string]bool{}
	var eps []clablinks.Endpoint
	for _, ep := range append(append([]clablinks.Endpoint(nil), n.parkedEndpoints...), n.Endpoints...) {
		if !seen[ep.GetIfaceName()] {
			seen[ep.GetIfaceName()] = true
			eps = append(eps, ep)
		}
	}
	return eps
}

// Generate interfaces configuration for IOL (and iouyap/netmap).
func (n *iol) GenInterfaceConfig(_ context.Context) error {
	iouyapData, netmapdata := n.interfaceConfig()

	// create IOUYAP and NETMAP file for interface mappings
	err := clabutils.CreateFile(path.Join(n.Cfg.LabDir, "iouyap.ini"), iouyapData)
	if err != nil {
		return err
	}
	err = clabutils.CreateFile(path.Join(n.Cfg.LabDir, "NETMAP"), netmapdata)

	return err
}

// interfaceConfig renders iouyap.ini and NETMAP and refills n.interfaces for the boot config.
func (n *iol) interfaceConfig() (iouyapData, netmapdata string) {
	// add default 'boilerplate' to NETMAP and iouyap.ini for management port (e0/0)
	iouyapData = "[default]\nbase_port = 49000\nnetmap = /iol/NETMAP\n"
	// A console node's Ethernet0/0 stays unplugged, like an unused port in GNS3: wired to the docker
	// mgmt bridge it would join every node of the lab behind the student's topology.
	if !n.consoleMode() {
		iouyapData += "[513:0/0]\neth_dev = eth0\n"
		netmapdata = fmt.Sprintf("%s:0/0 513:0/0\n", n.Pid)
	}

	// NTG-333: IOL reads NETMAP only at boot, so a node booted with fixed slots maps every port now
	// and a cable added later needs only iouyap.ini and an iouyap restart.
	fixedPorts := parseSlots(n.Cfg.Env[envNumSlots]) * 4
	for x := 1; x < fixedPorts; x++ {
		netmapdata += fmt.Sprintf("%s:%d/%d 513:%d/%d\n", n.Pid, x/4, x%4, x/4, x%4)
	}

	n.interfaces = nil
	for _, intf := range n.interfaceEndpoints() {
		x := ifIndex(intf.GetIfaceName())

		// Interface naming is Ethernet{slot}/{port}. Each slot contains max 4 ports
		slot := x / 4
		port := x % 4

		// append data to write to NETMAP and IOUYAP files
		iouyapData += fmt.Sprintf("[513:%d/%d]\neth_dev = %s\n", slot, port, intf.GetIfaceName())
		if x >= fixedPorts {
			netmapdata += fmt.Sprintf("%s:%d/%d 513:%d/%d\n", n.Pid, slot, port, slot, port)
		}

		// populate template array for config
		ipv4Addr := ""
		ipv4Mask := ""
		v4Prefix := intf.GetIPv4Addr()
		ipv6Addr := ""

		if v4Prefix.IsValid() {
			ipv4Addr = v4Prefix.Addr().String()
			ipv4Mask = clabutils.CIDRToDDN(v4Prefix.Bits())
		}

		if a := intf.GetIPv6Addr(); a.IsValid() {
			ipv6Addr = a.String()
		}

		n.interfaces = append(n.interfaces,
			IOLInterface{
				IfaceName: intf.GetIfaceName(),
				IfaceIdx:  x,
				Slot:      slot,
				Port:      port,
				IPv4Addr:  ipv4Addr,
				IPv4Mask:  ipv4Mask,
				IPv6Addr:  ipv6Addr,
			},
		)
	}

	return iouyapData, netmapdata
}

// Regexp to pull number out of linux'ethX' interface naming
var ifIndexRegexp = regexp.MustCompile(`\d+`)

func ifIndex(ifName string) int {
	x, _ := strconv.Atoi(ifIndexRegexp.FindString(ifName))
	return x
}

// NTG-333: an image with this label boots IOL with that many Ethernet slots (env envNumSlots, read
// by the image entrypoint), whatever is cabled at boot.
const (
	fixedSlotsLabel = "org.netgrader.iol.fixed-slots"
	envNumSlots     = "CLAB_IOL_NUM_SLOTS"
)

// iouyapRestart is Elysia's NTG-194 restart: IOS keeps running with its unsaved config.
const iouyapRestart = `for p in /proc/[0-9]*; do case "$(tr "\0" " " < $p/cmdline 2>/dev/null)" in "/usr/bin/iouyap 513 -q ") kill ${p#/proc/};; esac; done; sleep 1; cd /iol && (setsid /usr/bin/iouyap 513 -q >/proc/1/fd/1 2>&1 &); sleep 1`

// parseSlots returns a slot count from 1 to 16, or 0.
func parseSlots(v string) int {
	s, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || s < 1 || s > 16 {
		return 0
	}
	return s
}

// fixedSlots is the image's fixed slot count, or 0 for an image without the label.
func (n *iol) fixedSlots(ctx context.Context) int {
	if n.fixedSlotsOK {
		return n.fixedSlotsN
	}
	n.fixedSlotsOK = true
	if n.Cfg.Image == "" || n.Runtime == nil {
		return 0
	}
	inspect, err := n.Runtime.InspectImage(ctx, n.Cfg.Image)
	if err != nil || inspect == nil {
		log.Debug("IOL image inspect failed; booting without fixed slots", "image", n.Cfg.Image, "error", err)
		return 0
	}
	n.fixedSlotsN = parseSlots(inspect.Config.Labels[fixedSlotsLabel])
	return n.fixedSlotsN
}

// runningSlots is the slot count the running container was started with, or 0 when it was not
// started with one (an older image or fork, whose NETMAP lists only the cabled ports) or is not running.
func (n *iol) runningSlots(ctx context.Context) int {
	if n.runningSlotsOK {
		return n.runningSlotsN
	}
	n.runningSlotsOK = true
	if n.Runtime == nil {
		return 0
	}
	res, err := n.Runtime.Exec(ctx, n.GetContainerName(),
		clabexec.NewExecCmdFromSlice([]string{"printenv", envNumSlots}))
	switch {
	case err == nil && res.GetReturnCode() == 0:
		n.runningSlotsN = parseSlots(res.GetStdOutString())
	case err == nil && res.GetReturnCode() == 1:
		// printenv: the variable is unset, so an older image or fork started the container.
	case n.GetContainerStatus(ctx) == clabruntime.Running:
		// NTG-353: a running container that could not be asked may take its cables live; recreating
		// it would lose its unsaved config, so apply stops instead of guessing.
		if err == nil {
			err = fmt.Errorf("exit %d: %s", res.GetReturnCode(), strings.TrimSpace(res.GetStdErrString()))
		}
		n.runningSlotsErr = fmt.Errorf("could not read %s: %w", envNumSlots, err)
	}
	return n.runningSlotsN
}

// LinkApplyModeError is why LinkApplyMode could not tell whether the node takes cable changes live.
func (n *iol) LinkApplyModeError() error {
	return n.runningSlotsErr
}

// LinkApplyMode is live only for a container booted with fixed slots that hold every cable;
// anything else is recreated as before (NTG-333).
func (n *iol) LinkApplyMode(ctx context.Context) clabnodes.LinkApplyMode {
	if slots := n.runningSlots(ctx); slots > 0 {
		fits := true
		for _, ep := range n.Endpoints {
			fits = fits && ifIndex(ep.GetIfaceName()) < slots*4
		}
		if fits {
			return clabnodes.LinkApplyModeLive
		}
	}
	return n.DefaultNode.LinkApplyMode(ctx)
}

// PostDeployEndpoints applies the cables apply added or removed on a running live-link node:
// iouyap reads iouyap.ini only at start, so it is rewritten and iouyap restarted (NTG-333).
// A container created in this run is skipped: its iouyap.ini is complete and its entrypoint starts
// iouyap a few seconds after boot, so a restart now would leave two.
func (n *iol) PostDeployEndpoints(ctx context.Context) error {
	if n.created || n.runningSlots(ctx) == 0 {
		return nil
	}
	iouyapData, _ := n.interfaceConfig()
	if err := clabutils.CreateFile(path.Join(n.Cfg.LabDir, "iouyap.ini"), iouyapData); err != nil {
		return err
	}
	res, err := n.Runtime.Exec(ctx, n.GetContainerName(),
		clabexec.NewExecCmdFromSlice([]string{"sh", "-c", iouyapRestart}))
	if err != nil {
		return fmt.Errorf("iouyap restart: %w", err)
	}
	if res.GetReturnCode() != 0 {
		return fmt.Errorf("iouyap restart (exit %d): %s", res.GetReturnCode(), strings.TrimSpace(res.GetStdErrString()))
	}
	log.Info("Restarted iouyap for link changes", "node", n.Cfg.ShortName)
	return nil
}

// consoleCfgTemplate (NTG-260): a console node is reached over con0, so it gets no admin user,
// vty/SSH or mgmt address (its Ethernet0/0 is not wired).
const consoleCfgTemplate = "hostname {{ .Hostname }}\n!\n{{ .PartialCfg }}\nend\n"

func (n *iol) GenBootConfig(_ context.Context) error {
	n.bootCfg = cfgTemplate
	if n.consoleMode() {
		n.bootCfg = consoleCfgTemplate
	}

	if n.Cfg.StartupConfig != "" {
		cfg, err := os.ReadFile(n.Cfg.StartupConfig)
		if err != nil {
			return err
		}

		if clabutils.IsPartialConfigFile(n.Cfg.StartupConfig) {
			n.partialStartupCfg = string(cfg)
		} else {
			n.bootCfg = string(cfg)
		}
	}

	// create startup config template
	tpl := IOLTemplateData{
		Hostname:           n.Cfg.ShortName,
		IsL2Node:           n.isL2Node,
		MgmtIPv4Addr:       n.Cfg.MgmtIPv4Address,
		MgmtIPv4SubnetMask: clabutils.CIDRToDDN(n.Cfg.MgmtIPv4PrefixLength),
		MgmtIPv4GW:         n.Cfg.MgmtIPv4Gateway,
		MgmtIPv6Addr:       n.Cfg.MgmtIPv6Address,
		MgmtIPv6PrefixLen:  n.Cfg.MgmtIPv6PrefixLength,
		MgmtIPv6GW:         n.Cfg.MgmtIPv6Gateway,
		DataIFaces:         n.interfaces,
		PartialCfg:         n.partialStartupCfg,
	}

	IOLCfgTpl, _ := template.New("clab-iol-default-config").Funcs(
		clabutils.CreateFuncs()).Parse(n.bootCfg)

	// generate the config
	buf := new(bytes.Buffer)
	err := IOLCfgTpl.Execute(buf, tpl)
	if err != nil {
		return err
	}

	return clabutils.CreateFile(path.Join(n.Cfg.LabDir, "boot_config.txt"), buf.String())
}

type IOLTemplateData struct {
	Hostname           string
	IsL2Node           bool
	MgmtIPv4Addr       string
	MgmtIPv4SubnetMask string
	MgmtIPv4GW         string
	MgmtIPv6Addr       string
	MgmtIPv6PrefixLen  int
	MgmtIPv6GW         string
	DataIFaces         []IOLInterface
	PartialCfg         string
}

// IOLInterface struct stores mapping info between
// IOL interface name and linux container interface.
type IOLInterface struct {
	IfaceName string
	IfaceIdx  int
	Slot      int
	Port      int
	IPv4Addr  string
	IPv4Mask  string
	IPv6Addr  string
}

func (*iol) GetMappedInterfaceName(ifName string) (string, error) {
	captureGroups, err := clabutils.GetRegexpCaptureGroups(CapturingIntfRegexp, ifName)
	if err != nil {
		return "", err
	}

	indexGroups := []string{"slot", "port"}
	parsedIndices := make(map[string]int)
	foundIndices := make(map[string]bool)

	for _, indexKey := range indexGroups {
		if index, found := captureGroups[indexKey]; found && index != "" {
			foundIndices[indexKey] = true
			parsedIndices[indexKey], err = strconv.Atoi(index)
			if err != nil {
				return "", fmt.Errorf(
					"%q parsed %s index %q could not be cast to an integer",
					ifName,
					indexKey,
					index,
				)
			}
			if parsedIndices[indexKey] < 0 {
				return "", fmt.Errorf(
					"%q parsed %q index %q does not match requirement >= 0",
					ifName,
					indexKey,
					index,
				)
			}
		} else {
			foundIndices[indexKey] = false
		}
	}

	// return an ethX interface name. Slots are in 'groups' of 4 interfaces each
	if foundIndices["slot"] && foundIndices["port"] {
		return fmt.Sprintf("eth%d", (parsedIndices["slot"]*4)+parsedIndices["port"]), nil
	} else {
		return "", fmt.Errorf("%q missing slot or port index", ifName)
	}
}

// AddEndpoint override maps the endpoint name to an ethX-based naming where necessary, before
// adding it to the node endpoints. Returns an error if the mapping goes wrong or if the
// interface name is NOT allowed.
func (n *iol) AddEndpoint(e clablinks.Endpoint) error {
	endpointName := e.GetIfaceName()
	var IFaceName, IFaceAlias string

	IFaceName = endpointName

	if !(DefaultIntfRegexp.MatchString(endpointName)) &&
		AllowedIntfRegexp.MatchString(endpointName) {
		log.Debugf("%s: %s needs mapping", n.Cfg.ShortName, endpointName)
		mappedName, err := n.GetMappedInterfaceName(endpointName)
		if err != nil {
			return fmt.Errorf(
				"%q interface name %q could not be mapped to an ethX-based interface name: %w\n%s",
				n.Cfg.ShortName,
				e.GetIfaceName(),
				err,
				IntfHelpMsg,
			)
		}
		log.Debugf(
			"Interface Mapping: Mapping interface %q (ifAlias) to %q (ifName)",
			endpointName,
			mappedName,
		)
		IFaceName = mappedName
		IFaceAlias = endpointName
	}

	e.SetIfaceName(IFaceName)
	// should be nil if ethX naming is used.
	e.SetIfaceAlias(IFaceAlias)
	n.Endpoints = append(n.Endpoints, e)

	return nil
}

func (n *iol) CheckInterfaceName() error {
	err := n.CheckInterfaceOverlap()
	if err != nil {
		return err
	}

	for _, e := range n.Endpoints {
		IFaceName := e.GetIfaceName()
		if MgmtIntfRegexp.MatchString(IFaceName) {
			return fmt.Errorf(
				"IOL Node: %q. Management interface Ethernet0/0, e0/0 or eth0 is not allowed",
				n.Cfg.ShortName,
			)
		}

		if !DefaultIntfRegexp.MatchString(IFaceName) {
			return fmt.Errorf(
				"IOL Node %q has an interface named %q which doesn't match the required pattern. %s",
				n.Cfg.ShortName,
				IFaceName,
				IntfHelpMsg,
			)
		}
	}

	return nil
}

func (n *iol) UpdateMgmtIntf(ctx context.Context) error {
	// NTG-180: without a mgmt IPv6 address these lines were "ipv6 address /0" (incomplete) and a
	// default route with no gateway.
	ipv6Addr, ipv6Route := "", ""
	if n.Cfg.MgmtIPv6Address != "" {
		ipv6Addr = fmt.Sprintf("ipv6 address %s/%d\r", n.Cfg.MgmtIPv6Address, n.Cfg.MgmtIPv6PrefixLength)
		ipv6Route = fmt.Sprintf("ipv6 route vrf clab-mgmt ::/0 Ethernet0/0 %s\r", n.Cfg.MgmtIPv6Gateway)
	}
	mgmt_str := fmt.Sprintf(
		"\renable\rconfig terminal\rinterface Ethernet0/0\rip address %s %s\rno ipv6 address\r%sexit\rip route vrf clab-mgmt 0.0.0.0 0.0.0.0 Ethernet0/0 %s\r%send\rwr\r",
		n.Cfg.MgmtIPv4Address,
		clabutils.CIDRToDDN(n.Cfg.MgmtIPv4PrefixLength),
		ipv6Addr,
		n.Cfg.MgmtIPv4Gateway,
		ipv6Route,
	)

	return n.Runtime.WriteToStdinNoWait(ctx, n.Cfg.ContainerID, []byte(mgmt_str))
}

// NTG-254: a node with this env set is reached only over its con0 console (the image's relay);
// it boots a blank config with no mgmt address, so nothing may type into it or SSH to it.
const envConsole = "CLAB_IOL_CONSOLE"

var consoleSaveCmd = []string{"/console-cmd", "write memory"}

func (n *iol) consoleMode() bool { return n.Cfg.Env[envConsole] == "1" }

// legacySSHArgs (NTG-194): IOL 15 only offers SHA-1 kex and ssh-rsa host keys, which OpenSSH 9
// leaves out by default. scrapligo runs ssh with -F /dev/null, so the host ssh_config cannot add them.
var legacySSHArgs = []string{
	"-o", "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1",
	"-o", "HostKeyAlgorithms=+ssh-rsa",
}

// writeMemoryResult (NTG-194): IOS ends a successful "write memory" with [OK]. response.Failed
// only recognises a few syntax errors, so anything without [OK] counts as a failed save.
func writeMemoryResult(output string, failed error) error {
	if failed != nil {
		return fmt.Errorf("write memory failed: %w", failed)
	}
	if !strings.Contains(output, "[OK]") {
		return fmt.Errorf("write memory did not report [OK]: %q", strings.TrimSpace(output))
	}
	return nil
}

func (n *iol) saveOverConsole(ctx context.Context) error {
	res, err := n.RunExec(ctx, clabexec.NewExecCmdFromSlice(consoleSaveCmd))
	if err != nil {
		return fmt.Errorf("console save failed: %w", err)
	}
	if res.GetReturnCode() != 0 {
		return fmt.Errorf("console save failed (exit %d): %s", res.GetReturnCode(), strings.TrimSpace(res.GetStdErrString()))
	}
	if err := writeMemoryResult(res.GetStdOutString(), nil); err != nil {
		return err
	}
	log.Infof("Saved running configuration over the console for node: %q", n.Cfg.ShortName)
	return nil
}

// SaveConfig is used for "clab save" functionality -- it saves the running config to the startup
// configuration.
func (n *iol) SaveConfig(ctx context.Context) (*clabnodes.SaveConfigResult, error) {
	if n.consoleMode() {
		return nil, n.saveOverConsole(ctx)
	}
	p, err := platform.NewPlatform(
		"cisco_iosxe",
		n.Cfg.LongName,
		options.WithAuthNoStrictKey(),
		options.WithAuthUsername(n.Cfg.Credentials.Username),
		options.WithAuthPassword(n.Cfg.Credentials.Password),
		options.WithSystemTransportOpenArgs(legacySSHArgs),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create platform; error: %+v", err)
	}

	d, err := p.GetNetworkDriver()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch network driver from the platform; error: %+v", err)
	}

	// Before Open, so an Open that spawned ssh and then failed is reaped too.
	defer reapSSH(d.Transport)

	err = d.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open driver; error: %+v", err)
	}

	defer d.Close()

	resp, err := d.SendCommand("write memory")
	if err != nil {
		return nil, fmt.Errorf("failed to send command; error: %+v", err)
	}
	if err := writeMemoryResult(resp.Result, resp.Failed); err != nil {
		return nil, err
	}

	log.Infof(
		"Successfully copied running configuration to startup configuration file for node: %q\n",
		n.Cfg.ShortName,
	)
	return nil, nil
}

// NTG-231: a node's PID was Index+1, its place among all node names sorted, so adding a node with
// an earlier name changed it. The pinned mgmt address does not change for the node's lifetime and
// is unique in the lab (the last octet is, on the /24 mgmt subnets NetGrader uses); 513+host keeps clear of the old PIDs (1..nodes) still running and of
// iouyap's 513.
//
// NTG-249: a router on the faculty LAN takes NG_IOL_PID, the last octet of its cloud address,
// because IOL derives interface MACs from the PID and the macvlan must carry a MAC no other lab
// uses. 1-254 keeps clear of 513 and the 514-767 range above.
func iolPid(env map[string]string, mgmtIPv4 string, index int) (int, error) {
	if v, ok := env["NG_IOL_PID"]; ok {
		pid, err := strconv.Atoi(v)
		if err != nil || pid < 1 || pid > 254 {
			return 0, fmt.Errorf("NG_IOL_PID %q must be 1-254", v)
		}
		return pid, nil
	}
	if ip := net.ParseIP(mgmtIPv4).To4(); ip != nil && ip[3] >= 1 && ip[3] <= 254 {
		return 513 + int(ip[3]), nil
	}
	pid := index + 1
	if pid == 513 || pid > 1023 {
		return 0, fmt.Errorf("IOL PID %d is out of range (1-1023, not 513); pin a mgmt-ipv4", pid)
	}
	return pid, nil
}

var legacyNvramName = regexp.MustCompile(`^nvram_\d{5}$`)

// nvramWritten reports whether IOL has written the file: clab's placeholder is one byte.
func nvramWritten(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.Mode().IsRegular() && info.Size() > 1
}

// adoptLegacyNvram copies, once, the config a lab deployed before NTG-231 kept in nvram_<PID>
// into nvram: the newest written file, which is the one the running IOL had mounted (IOL writes
// its NVRAM at boot and on every save). Index+1 only breaks a tie, because the apply that
// recreates the node has usually changed its Index already. The original stays, for a rollback.
func (n *iol) adoptLegacyNvram() error {
	if nvramWritten(n.hostNvram) {
		return nil
	}
	entries, err := os.ReadDir(n.Cfg.LabDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	indexFile := fmt.Sprintf("nvram_%05d", n.Cfg.Index+1)
	src := ""
	var newest time.Time
	var candidates []string
	for _, e := range entries { // sorted by name
		p := path.Join(n.Cfg.LabDir, e.Name())
		if !legacyNvramName.MatchString(e.Name()) || e.Name() == "nvram_00000" || !nvramWritten(p) {
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		candidates = append(candidates, e.Name())
		switch mtime := info.ModTime(); {
		case src == "" || mtime.After(newest):
			newest, src = mtime, p
		case mtime.Equal(newest) && path.Base(src) != indexFile:
			src = p // a later (larger) name, unless Index+1 already holds the tie
		}
	}
	if src == "" {
		return nil
	}
	if len(candidates) > 1 {
		log.Warn("IOL node has several saved NVRAM files; using the newest",
			"node", n.Cfg.ShortName, "files", candidates, "using", path.Base(src))
	}
	log.Info("IOL NVRAM moved to the per-node file (NTG-231)", "node", n.Cfg.ShortName, "from", path.Base(src))
	return copyFileAtomic(src, n.hostNvram)
}

// copyFileAtomic copies src to dst through a temp file in dst's directory, with src's owner and
// mode, so dst is either absent or complete.
func copyFileAtomic(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.CreateTemp(path.Dir(dst), ".nvram.tmp-*")
	if err != nil {
		return err
	}
	tmp := out.Name()
	defer func() {
		if err != nil {
			out.Close()
			os.Remove(tmp)
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if err = out.Chown(int(st.Uid), int(st.Gid)); err != nil {
			return err
		}
	}
	if err = out.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if err = out.Sync(); err != nil {
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// reapSSH waits for the ssh child of scrapligo's system transport. scrapligo v1's Close kills
// ssh but never waits for it, which left one zombie under clab-api-server per save (NTG-255).
// ponytail: reads scrapligo's unexported cmd field; if a version renames it this is a no-op and
// TestReapSystemTransportLeavesNoZombie fails. Drop it when scrapligo waits in Close.
func reapSSH(tr *transport.Transport) {
	sys, ok := tr.Impl.(*transport.System)
	if !ok {
		return
	}
	f := reflect.ValueOf(sys).Elem().FieldByName("c")
	if !f.IsValid() || f.Kind() != reflect.Pointer || f.IsNil() {
		return
	}
	cmd := (*exec.Cmd)(f.UnsafePointer())
	if cmd.Process == nil || cmd.ProcessState != nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}
