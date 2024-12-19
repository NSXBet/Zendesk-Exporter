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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	sc = config.SafeConfig{
		C: &config.Config{},
	}

	logger zerolog.Logger

	configFile    = kingpin.Flag("config.file", "Compteur configuration file.").Default("zendesk.yml").String()
	listenAddress = kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests.").Default(":9146").String()
	logLevel      = kingpin.Flag("log.level", "Only log messages with the given severity or above. Valid levels: [debug, info, warn, error, fatal]").Default("info").String()
)

func init() {
	prometheus.MustRegister(collectors.NewBuildInfoCollector())
	prometheus.MustRegister(version.NewCollector("zendesk_exporter"))
}

func setZendeskClient(z *config.Zendesk) (*zendesk.Client, error) {
	if z.Token != "" {
		return zendesk.NewClientByToken(z.URL, z.Login, z.Token)
	}
	return zendesk.NewClientByPassword(z.URL, z.Login, z.Password)
}

func zendeskHandler(w http.ResponseWriter, r *http.Request, z *zendesk.Client, f *config.Filter) {
	logger.Debug().Msg("Handling /zendesk request")

	registry := prometheus.NewRegistry()
	collector := collector{zenClient: z, filter: f}
	registry.MustRegister(collector)

	logger.Debug().Msg("Collector registered, serving metrics")
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func main() {
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	level, err := zerolog.ParseLevel(*logLevel)
	if err != nil {
		fmt.Printf("Invalid log level %q: %v\n", *logLevel, err)
		os.Exit(1)
	}
	zerolog.SetGlobalLevel(level)
	logger = log.With().Caller().Logger()

	logger.Info().Msg("Starting Zendesk-Exporter")

	if err := sc.ReloadConfig(*configFile); err != nil {
		logger.Error().Err(err).Msg("Error loading config")
		os.Exit(1)
	}
	logger.Info().Msg("Loaded config file")
	sc.Lock()
	conf := sc.C
	sc.Unlock()

	hup := make(chan os.Signal, 1)
	reloadCh := make(chan chan error)
	signal.Notify(hup, syscall.SIGHUP)

	go func() {
		for {
			select {
			case <-hup:
				if err := sc.ReloadConfig(*configFile); err != nil {
					logger.Error().Err(err).Msg("Error reloading config")
					continue
				}
				logger.Info().Msg("Reloaded config file")
			case rc := <-reloadCh:
				if err := sc.ReloadConfig(*configFile); err != nil {
					logger.Error().Err(err).Msg("Error reloading config")
					rc <- err
				} else {
					logger.Info().Msg("Reloaded config file")
					rc <- nil
				}
			}
		}
	}()

	zen, err := setZendeskClient(&conf.Zendesk)
	if err != nil {
		logger.Error().Err(err).Msg("Error setting Zendesk client")
		os.Exit(1)
	}

	logger.Info().Msg("Testing Zendesk connection...")
	logger.Debug().
		Str("url", conf.Zendesk.URL).
		Str("login", conf.Zendesk.Login).
		Str("auth_type", map[bool]string{true: "token", false: "password"}[conf.Zendesk.Token != ""]).
		Str("full_url", fmt.Sprintf("https://%s.zendesk.com/api/v2", conf.Zendesk.URL)).
		Msg("Using credentials")

	if _, err := zen.GetTicketStats(); err != nil {
		logger.Error().
			Err(err).
			Str("url", conf.Zendesk.URL).
			Str("login", conf.Zendesk.Login).
			Str("request_url", fmt.Sprintf("https://%s.zendesk.com/api/v2/tickets.json", conf.Zendesk.URL)).
			Msg("Failed to connect to Zendesk")
		os.Exit(1)
	}
	logger.Info().Msg("Successfully connected to Zendesk")

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

	logger.Info().Str("address", *listenAddress).Msg("Listening on")
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		logger.Error().Err(err).Msg("Error starting HTTP server")
		os.Exit(1)
	}
	m, err := zen.GetTicketStats()
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(m)
	}
}
