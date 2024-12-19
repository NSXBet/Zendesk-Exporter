package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/NSXBet/Zendesk-Exporter/src/config"
	"github.com/NSXBet/Zendesk-Exporter/src/zendesk"

	kingpin "github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
)

var (
	sc = config.SafeConfig{
		C: &config.Config{},
	}

	logger log.Logger

	configFile    = kingpin.Flag("config.file", "Compteur configuration file.").Default("zendesk.yml").String()
	listenAddress = kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests.").Default(":9146").String()
	logLevel      = kingpin.Flag("log.level", "Only log messages with the given severity or above. Valid levels: [debug, info, warn, error, fatal]").Default("info").String()
)

func init() {
	prometheus.MustRegister(prometheus.NewBuildInfoCollector())
	prometheus.MustRegister(version.NewCollector("zendesk_exporter"))
}

func setZendeskClient(z *config.Zendesk) (*zendesk.Client, error) {
	if z.Token != "" {
		return zendesk.NewClientByToken(z.URL, z.Login, z.Token)
	}
	return zendesk.NewClientByPassword(z.URL, z.Login, z.Password)
}

func zendeskHandler(w http.ResponseWriter, r *http.Request, z *zendesk.Client, f *config.Filter) {
	registry := prometheus.NewRegistry()
	collector := collector{zenClient: z, filter: f}
	registry.MustRegister(collector)

	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func main() {
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	logger = level.NewFilter(logger, level.AllowInfo())
	if *logLevel != "" {
		switch *logLevel {
		case "debug":
			logger = level.NewFilter(logger, level.AllowDebug())
		case "info":
			logger = level.NewFilter(logger, level.AllowInfo())
		case "warn":
			logger = level.NewFilter(logger, level.AllowWarn())
		case "error":
			logger = level.NewFilter(logger, level.AllowError())
		default:
			fmt.Printf("Unrecognized log level: %v\n", *logLevel)
			os.Exit(1)
		}
	}

	level.Info(logger).Log("msg", "Starting Zendesk-Exporter")

	if err := sc.ReloadConfig(*configFile); err != nil {
		level.Error(logger).Log("msg", "Error loading config", "err", err)
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Loaded config file")
	sc.Lock()
	conf := sc.C
	sc.Unlock()

	hup := make(chan os.Signal)
	reloadCh := make(chan chan error)
	signal.Notify(hup, syscall.SIGHUP)

	go func() {
		for {
			select {
			case <-hup:
				if err := sc.ReloadConfig(*configFile); err != nil {
					level.Error(logger).Log("msg", "Error reloading config", "err", err)
					continue
				}
				level.Info(logger).Log("msg", "Reloaded config file")
			case rc := <-reloadCh:
				if err := sc.ReloadConfig(*configFile); err != nil {
					level.Error(logger).Log("msg", "Error reloading config", "err", err)
					rc <- err
				} else {
					level.Info(logger).Log("msg", "Reloaded config file")
					rc <- nil
				}
			}
		}
	}()

	zen, err := setZendeskClient(&conf.Zendesk)
	if err != nil {
		level.Error(logger).Log("msg", "Error setting Zendesk client", "err", err)
		os.Exit(1)
	}

	http.HandleFunc("/-/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintf(w, "This endpoint requires a POST request.\n")
			return
		}

		rc := make(chan error)
		reloadCh <- rc
		if err := <-rc; err != nil {
			http.Error(w, fmt.Sprintf("Failed to reload config: %s", err), http.StatusInternalServerError)
			return
		}
		tmp, err := setZendeskClient(&conf.Zendesk)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to reload config: %s", err), http.StatusInternalServerError)
			return
		}
		zen = tmp
	})

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/zendesk", func(w http.ResponseWriter, r *http.Request) {
		sc.Lock()
		conf := sc.C
		sc.Unlock()
		zendeskHandler(w, r, zen, &conf.Filter)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
			<html>
				<head>
					<title>Zendesk-Exporter</title>
				</head>
				<body>
					<h1>Zendesk-Exporter</h1>
					<p><a href="/zendesk">Zendesk Statistics</a></p>
				</body>
			</html>`))
	})

	level.Info(logger).Log("msg", "Listening on", "address", *listenAddress)
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}
	m, err := zen.GetTicketStats()
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(m)
	}
}
