// Command l2-connectivity checks layer 2 reachability between machines using
// raw Ethernet frames only (no IP).
//
//	l2-connectivity agent -i wlan0   # run on every machine: discover, probe, show matrix
//	l2-connectivity sniff -i wlan0   # passive: list MACs whose frames reach us
//
// Linux only (AF_PACKET), needs root or CAP_NET_RAW.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage: %s <command> [flags]

commands:
  agent   run on every node: broadcast HELLOs, probe peers, print RTT/loss/MTU matrix
  sniff   passively list source MACs seen on the interface

run "%s <command> -h" for the command's flags
`, os.Args[0], os.Args[0])
}

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "agent":
		os.Exit(agentMain(os.Args[2:]))
	case "sniff":
		os.Exit(sniffMain(os.Args[2:]))
	case "-h", "-help", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func agentMain(args []string) int {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	hostname, _ := os.Hostname()
	cfg := agentConfig{}
	fs.StringVar(&cfg.iface, "i", "", "interface to use (required), e.g. wlan0, mesh0, bat0")
	fs.StringVar(&cfg.name, "name", hostname, "name announced to other nodes")
	etherType := fs.String("ethertype", fmt.Sprintf("0x%04x", defaultEtherType), "EtherType for our frames (all nodes must match)")
	fs.DurationVar(&cfg.helloEvery, "hello", time.Second, "HELLO broadcast interval (keep equal on all nodes)")
	fs.DurationVar(&cfg.probeEvery, "interval", time.Second, "unicast ping probe interval per peer")
	fs.IntVar(&cfg.probeSize, "size", 64, "ping probe size in bytes (Ethernet payload)")
	fs.DurationVar(&cfg.mtuEvery, "mtu-interval", 5*time.Second, "path MTU probe round interval")
	fs.DurationVar(&cfg.timeout, "timeout", time.Second, "probe reply timeout; later replies count as lost")
	fs.IntVar(&cfg.window, "window", 100, "number of recent probes/HELLOs used for loss and RTT")
	fs.DurationVar(&cfg.forget, "forget", 5*time.Minute, "drop peers with no sign of life for this long")
	fs.DurationVar(&cfg.reportEvery, "report", 2*time.Second, "matrix refresh interval")
	fs.DurationVar(&cfg.duration, "duration", 0, "run this long, print the final matrix and exit (0 = until Ctrl-C)")
	fs.Func("peer", "peer MAC to probe even if its HELLOs are not heard (repeatable)", func(s string) error {
		hw, err := net.ParseMAC(s)
		if err != nil || len(hw) != 6 {
			return fmt.Errorf("bad MAC %q", s)
		}
		cfg.staticPeers = append(cfg.staticPeers, hw)
		return nil
	})
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: %s agent -i <iface> [flags]\n\n", os.Args[0])
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), "\nexit status with -duration: 0 every peer answers, 1 some peer never answers, 2 no peer found\n")
	}
	fs.Parse(args)

	if cfg.iface == "" {
		fs.Usage()
		return 2
	}
	et, err := strconv.ParseUint(*etherType, 0, 16)
	if err != nil || et < 0x0600 {
		log.Printf("bad -ethertype %q", *etherType)
		return 2
	}
	cfg.etherType = int(et)
	if cfg.probeSize < minProbeSize {
		cfg.probeSize = minProbeSize
	}
	if cfg.window < 1 {
		cfg.window = 1
	}

	code, err := runAgent(cfg)
	if err != nil {
		log.Print(err)
		return 3
	}
	return code
}

func sniffMain(args []string) int {
	fs := flag.NewFlagSet("sniff", flag.ExitOnError)
	cfg := sniffConfig{}
	fs.StringVar(&cfg.iface, "i", "", "interface to listen on (required)")
	fs.BoolVar(&cfg.promisc, "promisc", false, "enable promiscuous mode (little effect on most Wi-Fi drivers)")
	fs.DurationVar(&cfg.reportEvery, "report", 2*time.Second, "table refresh interval")
	fs.DurationVar(&cfg.duration, "duration", 0, "run this long, print the final table and exit (0 = until Ctrl-C)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: %s sniff -i <iface> [flags]\n\n", os.Args[0])
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if cfg.iface == "" {
		fs.Usage()
		return 2
	}
	if err := runSniff(cfg); err != nil {
		log.Print(err)
		return 3
	}
	return 0
}
