package ebpftracer

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type TracerConfig struct {
	StatExportInterval time.Duration
}

type Tracer struct {
	log          *slog.Logger
	programLinks tracerEBPFState
	cfg          TracerConfig
}

type tracerEBPFState struct {
	cgroupIngress    link.Link
	cgroupEgress     link.Link
	cgroupSockCreate link.Link
	objs             *tracerObjects
	spec             *ebpf.CollectionSpec
	mapBufferSpec    *ebpf.MapSpec
}

func New(log *slog.Logger, cfg TracerConfig) *Tracer {
	if cfg.StatExportInterval == 0 {
		cfg.StatExportInterval = 5 * time.Second
	}

	return &Tracer{
		log: log,
		cfg: cfg,
	}
}

func buildMapBufferMap(originalSpec *ebpf.MapSpec) (*ebpf.Map, error) {
	spec := originalSpec.Copy()
	spec.Contents = make([]ebpf.MapKV, spec.MaxEntries)

	for i := uint32(0); i < spec.MaxEntries; i++ {
		innerSpec := spec.InnerMap.Copy()
		innerSpec.Name = fmt.Sprintf("sum_map_%d", i)

		innerMap, err := ebpf.NewMap(innerSpec)
		if err != nil {
			return nil, err
		}
		defer innerMap.Close()

		spec.Contents[i] = ebpf.MapKV{Key: i, Value: innerMap}
	}

	outerMap, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, err
	}

	return outerMap, nil
}

func (t *Tracer) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("error while removing memlock: %w", err)
	}

	var objs tracerObjects

	spec, err := loadTracer()
	if err != nil {
		return fmt.Errorf("error while loading ebpf spec: %w", err)
	}

	mapBufferSpec, found := spec.Maps["sum_map_buffer"]
	if !found {
		return fmt.Errorf("error sum_map_buffer map spec not found")
	}
	summaryMapBuffer, err := buildMapBufferMap(mapBufferSpec)
	if err != nil {
		return fmt.Errorf("erro while building summary map buffer: %w", err)
	}

	err = spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"sum_map_buffer": summaryMapBuffer,
		},
	})
	if err != nil {
		return fmt.Errorf("error while loading ebpf objects: %w", err)
	}

	cgroupPath, err := detectCgroupPath()
	if err != nil {
		return fmt.Errorf("error while detecting cgroup path: %w", err)
	}

	cgroupSockCreate, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: objs.CgroupSockCreate,
	})
	if err != nil {
		return fmt.Errorf("error while attaching cgroup sock create probe: %w", err)
	}

	cgroupIngress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: objs.CgroupSkbIngress,
	})
	if err != nil {
		return fmt.Errorf("error while attaching cgroup ingress probe: %w", err)
	}

	cgroupEgress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.CgroupSkbEgress,
	})
	if err != nil {
		return fmt.Errorf("error while attaching cgroup egress probe: %w", err)
	}

	t.programLinks = tracerEBPFState{
		cgroupIngress:    cgroupIngress,
		cgroupEgress:     cgroupEgress,
		cgroupSockCreate: cgroupSockCreate,
		objs:             &objs,
		spec:             spec,
		mapBufferSpec:    mapBufferSpec,
	}

	return nil
}

func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}

func (t *Tracer) RunStatLoop(ctx context.Context) error {
	ticker := time.NewTicker(t.cfg.StatExportInterval)

	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return nil
		case <-ticker.C:
			stats, err := t.collectStats()
			if err != nil {
				return err
			}

			fmt.Println("==== Stats ====")
			for ipKey, trafficSummary := range stats {
				var processName string
				parts := bytes.SplitN(ipKey.ProcessIdentity.Name[:], []byte{0}, 2)
				if len(parts[0]) > 0 {
					processName = string(parts[0])
				} else {
					processName = "<<unknown>>"
				}

				var (
					daddr netip.Addr
					saddr netip.Addr
				)

				switch ipKey.Tuple.Family {
				case AFInet:
					if ip, ok := netip.AddrFromSlice(ipKey.Tuple.Saddr.Raw[:4]); ok {
						saddr = ip
					} else {
						t.log.Warn("cannot parse source addr v4", slog.Any("addr", ipKey.Tuple.Saddr.Raw[:4]))
					}

					if ip, ok := netip.AddrFromSlice(ipKey.Tuple.Daddr.Raw[:4]); ok {
						daddr = ip
					} else {
						t.log.Warn("cannot parse destination addr v4", slog.Any("addr", ipKey.Tuple.Daddr.Raw[:4]))
					}
				case AFInet6:
					daddr = netip.AddrFrom16(ipKey.Tuple.Daddr.Raw)
					saddr = netip.AddrFrom16(ipKey.Tuple.Saddr.Raw)
				}

				fmt.Printf("%s(%d): %s:%d -> %s:%d TX: %d RX: %d TX_Packets: %d RX_Packets: %d\n",
					processName, ipKey.ProcessIdentity.Pid,
					saddr, ipKey.Tuple.Lport, daddr, ipKey.Tuple.Dport,
					trafficSummary.TxBytes, trafficSummary.RxBytes,
					trafficSummary.TxPackets, trafficSummary.RxPackets,
				)
			}
		}

	}
}

type ProcessIdentity = tracerProcessIdentity
type TrafficKey = tracerIpKey
type TrafficSummary = tracerTrafficSummary

func (t *Tracer) collectStats() (map[TrafficKey]TrafficSummary, error) {
	var config tracerConfig

	numEntries := t.programLinks.objs.SumMapBuffer.MaxEntries()
	zero := uint32(0)

	err := t.programLinks.objs.ConfigMap.Lookup(zero, &config)
	if err != nil {
		return nil, fmt.Errorf("error while config lookup: %w", err)
	}

	indexToHarvest := config.SummaryMapIndex
	config.SummaryMapIndex = (config.SummaryMapIndex + 1) % int32(numEntries)

	err = t.programLinks.objs.ConfigMap.Update(zero, &config, ebpf.UpdateExist)
	if err != nil {
		return nil, fmt.Errorf("error while updating config: %w", err)
	}

	innerMapSpec := t.programLinks.mapBufferSpec.InnerMap.Copy()
	if innerMapSpec == nil {
		return nil, errors.New("error: no inner map spec")
	}
	innerMapSpec.Name = fmt.Sprintf("sum_map_%d", indexToHarvest)

	newMap, err := ebpf.NewMap(innerMapSpec)
	if err != nil {
		return nil, fmt.Errorf("error while creating new inner map: %w", err)
	}
	defer newMap.Close()

	var summaryMap *ebpf.Map
	err = t.programLinks.objs.SumMapBuffer.Lookup(indexToHarvest, &summaryMap)
	if err != nil {
		return nil, fmt.Errorf("error while getting existing map: %w", err)
	}
	defer summaryMap.Close()

	err = t.programLinks.objs.SumMapBuffer.Update(indexToHarvest, newMap, ebpf.UpdateAny)
	if err != nil {
		return nil, fmt.Errorf("error while replacing existing map: %w", err)
	}

	iter := summaryMap.Iterate()
	var ipKey TrafficKey
	var trafficSummary TrafficSummary

	result := map[TrafficKey]TrafficSummary{}

	for iter.Next(&ipKey, &trafficSummary) {
		result[ipKey] = trafficSummary
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterator finished with error: %w", err)
	}

	return result, nil
}
