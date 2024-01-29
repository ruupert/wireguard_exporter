// Command wireguard_exporter implements a Prometheus exporter for WireGuard
// devices.
package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-kit/log/level"

	"github.com/alecthomas/kingpin/v2"

	wireguardexporter "github.com/mdlayher/wireguard_exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func main() {

	var (
		toolkitFlags = kingpinflag.AddFlags(kingpin.CommandLine, ":9586")
		metricsPath  = kingpin.Flag("metrics.path", "URL path for surfacing collected metrics").Default("/metrics").String()
		wgPeerNames  = kingpin.Flag("wireguard.peer-names", `optional: comma-separated list of colon-separated public keys and friendly peer names, such as: "keyA:foo,keyB:bar"`).Default("").String()
		wgPeerFile   = kingpin.Flag("wireguard.peer-file", "optional: path to TOML friendly peer names mapping file; takes priority over -wireguard.peer-names").Default("").String()
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("wireguard_exporter"))
	kingpin.CommandLine.UsageWriter(os.Stdout)
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	client, err := wgctrl.New()
	if err != nil {
		log.Fatalf("failed to open WireGuard control client: %v", err)
	}
	defer client.Close()

	if _, err := client.Devices(); err != nil {
		log.Fatalf("failed to fetch WireGuard devices: %v", err)
	}

	// Configure the friendly peer names map if the flag is not empty.
	peerNames := make(map[string]string)
	if *wgPeerNames != "" {
		for _, kvs := range strings.Split(*wgPeerNames, ",") {
			kv := strings.Split(kvs, ":")
			if len(kv) != 2 {
				log.Fatalf("failed to parse %q as a valid public key and peer name", kv)
			}

			peerNames[kv[0]] = kv[1]
		}

		log.Printf("loaded %d peer name mappings from command line", len(peerNames))
	}

	// In addition, load peer name mappings from a file if specified.
	if file := *wgPeerFile; file != "" {
		f, err := os.Open(file)
		if err != nil {
			log.Fatalf("failed to open peer names file: %v", err)
		}
		defer f.Close()

		names, err := wireguardexporter.ParsePeers(f)
		if err != nil {
			log.Fatalf("failed to parse peer names file: %v", err)
		}
		_ = f.Close()

		log.Printf("loaded %d peer name mappings from file %q", len(names), file)

		// Merge file name mappings and overwrite CLI mappings if necessary.
		for k, v := range names {
			peerNames[k] = v
		}
	}

	// Make Prometheus client aware of our collector.
	c := wireguardexporter.New(client.Devices, peerNames)
	prometheus.MustRegister(c)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, *metricsPath, http.StatusMovedPermanently)
	})

	server := &http.Server{}
	if err := web.ListenAndServe(server, toolkitFlags, logger); err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}

}
