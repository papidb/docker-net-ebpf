package prometheusoutput

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"docker-net-ebpf/netwatch"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const defaultAddr = ":9099"

type Output struct {
	mu       sync.Mutex
	samples  []netwatch.TrafficSample
	server   *http.Server
	registry *prometheus.Registry

	rxBytes    *prometheus.Desc
	txBytes    *prometheus.Desc
	rxPackets  *prometheus.Desc
	txPackets  *prometheus.Desc
}

func New(addr string) (*Output, error) {
	if addr == "" {
		addr = defaultAddr
	}

	o := &Output{
		registry: prometheus.NewRegistry(),
		rxBytes: prometheus.NewDesc(
			"netwatch_rx_bytes_total",
			"Total received bytes",
			[]string{"container", "container_id", "remote_ip", "protocol"}, nil,
		),
		txBytes: prometheus.NewDesc(
			"netwatch_tx_bytes_total",
			"Total transmitted bytes",
			[]string{"container", "container_id", "remote_ip", "protocol"}, nil,
		),
		rxPackets: prometheus.NewDesc(
			"netwatch_rx_packets_total",
			"Total received packets",
			[]string{"container", "container_id", "remote_ip", "protocol"}, nil,
		),
		txPackets: prometheus.NewDesc(
			"netwatch_tx_packets_total",
			"Total transmitted packets",
			[]string{"container", "container_id", "remote_ip", "protocol"}, nil,
		),
	}

	o.registry.MustRegister(o)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(o.registry, promhttp.HandlerOpts{}))

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	o.server = &http.Server{Handler: mux}

	go o.server.Serve(ln)

	return o, nil
}

func (o *Output) Write(_ context.Context, samples []netwatch.TrafficSample) error {
	o.mu.Lock()
	o.samples = samples
	o.mu.Unlock()
	return nil
}

func (o *Output) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return o.server.Shutdown(ctx)
}

func (o *Output) Describe(ch chan<- *prometheus.Desc) {
	ch <- o.rxBytes
	ch <- o.txBytes
	ch <- o.rxPackets
	ch <- o.txPackets
}

func (o *Output) Collect(ch chan<- prometheus.Metric) {
	o.mu.Lock()
	samples := o.samples
	o.mu.Unlock()

	for _, s := range samples {
		remoteIP := ""
		if s.Remote.Addr.IsValid() {
			remoteIP = s.Remote.Addr.String()
		}
		proto := s.Remote.Protocol.String()
		containerID := s.Container.ID
		if len(containerID) > 12 {
			containerID = containerID[:12]
		}

		labels := []string{s.Container.Name, containerID, remoteIP, proto}

		ch <- prometheus.MustNewConstMetric(o.rxBytes, prometheus.CounterValue, float64(s.RxBytesTotal), labels...)
		ch <- prometheus.MustNewConstMetric(o.txBytes, prometheus.CounterValue, float64(s.TxBytesTotal), labels...)
		ch <- prometheus.MustNewConstMetric(o.rxPackets, prometheus.CounterValue, float64(s.RxPacketsTotal), labels...)
		ch <- prometheus.MustNewConstMetric(o.txPackets, prometheus.CounterValue, float64(s.TxPacketsTotal), labels...)
	}
}
