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
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/charmbracelet/log"
	"github.com/scrapli/scrapligo/driver/options"
	"github.com/scrapli/scrapligo/platform"
	clabconstants "github.com/srl-labs/containerlab/constants"
	clablinks "github.com/srl-labs/containerlab/links"
	clabnodes "github.com/srl-labs/containerlab/nodes"
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

	pid, err := iolPid(n.Cfg.MgmtIPv4Address, n.Cfg.Index)
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

	// Must update mgmt IP if not first boot
	if !n.firstBoot {
		// iol has a 5sec boot delay, wait a few extra secs for the console
		time.Sleep(10 * time.Second)

		return n.UpdateMgmtIntf(ctx)
	}

	return nil
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

// Generate interfaces configuration for IOL (and iouyap/netmap).
func (n *iol) GenInterfaceConfig(_ context.Context) error {
	// add default 'boilerplate' to NETMAP and iouyap.ini for management port (e0/0)
	iouyapData := "[default]\nbase_port = 49000\nnetmap = /iol/NETMAP\n[513:0/0]\neth_dev = eth0\n"
	netmapdata := fmt.Sprintf("%s:0/0 513:0/0\n", n.Pid)

	slot, port := 0, 0

	// Regexp to pull number out of linux'ethX' interface naming
	IntfRegExpr := regexp.MustCompile(`\d+`)

	for _, intf := range n.Endpoints {
		// get numeric interface number and cast to int
		x, _ := strconv.Atoi(IntfRegExpr.FindString(intf.GetIfaceName()))

		// Interface naming is Ethernet{slot}/{port}. Each slot contains max 4 ports
		slot = x / 4
		port = x % 4

		// append data to write to NETMAP and IOUYAP files
		iouyapData += fmt.Sprintf("[513:%d/%d]\neth_dev = %s\n", slot, port, intf.GetIfaceName())
		netmapdata += fmt.Sprintf("%s:%d/%d 513:%d/%d\n", n.Pid, slot, port, slot, port)

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

	// create IOUYAP and NETMAP file for interface mappings
	err := clabutils.CreateFile(path.Join(n.Cfg.LabDir, "iouyap.ini"), iouyapData)
	if err != nil {
		return err
	}
	err = clabutils.CreateFile(path.Join(n.Cfg.LabDir, "NETMAP"), netmapdata)

	return err
}

func (n *iol) GenBootConfig(_ context.Context) error {
	n.bootCfg = cfgTemplate

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

// SaveConfig is used for "clab save" functionality -- it saves the running config to the startup
// configuration.
func (n *iol) SaveConfig(_ context.Context) (*clabnodes.SaveConfigResult, error) {
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
func iolPid(mgmtIPv4 string, index int) (int, error) {
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
