package proc

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"patrickpichler.dev/ebpf-net-tracer/pkg/system"
)

type Sock struct {
	Inode  uint64
	Local  netip.AddrPort
	Remote netip.AddrPort
}

type Process struct {
	PID  PID
	PPID PID
	Args []string
	// StartTime since boot start
	StartTime time.Duration
	FilePath  string
	Socks     []Sock
}

// SnapshotProcessTree records a snappshot of the current process tree in the PID namespace of the
// given targetPID. This is done by iterating over files exposed from the `/proc` filesystem.
func (p *Proc) SnapshotProcessTree(targetPID PID) ([]Process, error) {
	targetPIDString := pidToString(targetPID)
	targetPath := filepath.Join(targetPIDString, "root", "proc")

	entries, err := p.procFS.ReadDir(targetPath)
	if err != nil {
		return nil, err
	}

	socks, err := p.parseSocks(targetPID)
	if err != nil {
		return nil, err
	}

	inodeToSock := map[uint64]Sock{}

	for _, s := range socks {
		fmt.Println("==", s)
		inodeToSock[s.Inode] = s
	}

	// This will always overshoot with memory, but still better than not pre-allocating.
	processes := make([]Process, 0, len(entries))

	for _, de := range entries {
		// We only care about processes, hence we test for numbers only folders.
		if !de.IsDir() || !numOnlyName(de.Name()) {
			continue
		}

		pid, err := parsePID(de.Name())
		if err != nil {
			return nil, err
		}

		if pid == 2 {
			// PID 2 will always be kthreadd, which we do not care about.
			continue
		}
		pidStr := pidToString(pid)

		data, err := p.procFS.ReadFile(
			filepath.Join(targetPath, pidToString(pid), "stat"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// A process can exit after we got the dir list. In such cases, we simply ignore it.
				continue
			}
			return nil, err
		}

		statData, err := getDataFromStat(data)
		if err != nil {
			return nil, err
		}

		if statData.PPID == 2 {
			// All processes under PID 2 (kthreadd) are kernel threads we do not want to display
			continue
		}

		processStartTime := system.TicksToDuration(statData.StartTime)

		// The symlink will be relative to the container root, so this should work just fine. Sadly symlink-support for FS is not merged
		// into go yet, hence we need to fall back to Readlink.
		path, err := os.Readlink(filepath.Join(Path, targetPath, pidStr, "exe"))
		if err != nil {
			// TODO(patrick.pichler): Figure out what to do on error
			path = ""
		}

		var cmdLine []string
		data, err = p.procFS.ReadFile(
			filepath.Join(targetPath, pidStr, "cmdline"))
		// A process can exit after we got the dir list. Do not mess up the process tree, we will still report the process.
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		} else {
			cmdLine = parseCmdline(data)
		}

		var socks []Sock

		fds, err := p.procFS.ReadDir(filepath.Join(targetPath, pidStr, "fd"))
		if err != nil {
			return nil, err
		}

		for _, entry := range fds {
			link, err := os.Readlink(filepath.Join(Path, targetPath, pidStr, "fd", entry.Name()))
			if err != nil {
				continue
			}

			if !strings.HasPrefix(link, "socket:[") {
				// We are only interested in sockets.
				continue
			}

			inoStr := link[len("socket:[") : len(link)-1]
			ino, err := strconv.ParseUint(inoStr, 10, 64)
			if err != nil {
				continue
			}

			sock, found := inodeToSock[ino]
			if !found {
				continue
			}

			socks = append(socks, sock)
		}

		processes = append(processes, Process{
			PID:       pid,
			PPID:      statData.PPID,
			Args:      cmdLine,
			StartTime: processStartTime,
			FilePath:  path,
			Socks:     socks,
		})
	}

	slices.SortFunc(processes, func(a, b Process) int {
		return cmp.Compare(a.PID, b.PID)
	})

	return processes, nil
}

func (p *Proc) parseSocks(targetPID PID) ([]Sock, error) {
	targetPIDString := pidToString(targetPID)
	targetPath := filepath.Join(targetPIDString, "root", "proc")

	var result []Sock

	for _, sockType := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := p.procFS.Open(filepath.Join(targetPath, "net", sockType))
		if err != nil {
			return nil, fmt.Errorf("error cannot open sock file of type `%s`: %w", sockType, err)
		}

		socks, err := parseSocksFile(f)
		if err != nil {
			return nil, fmt.Errorf("error cannot parse sock types `%s`: %w", sockType, err)
		}

		result = append(result, socks...)
	}

	return result, nil
}

func parseSocksFile(f fs.File) ([]Sock, error) {
	s := bufio.NewScanner(f)

	// The first line is the header, which we do not care about
	_ = s.Scan()

	var result []Sock

	for s.Scan() {
		data := s.Bytes()
		fields := strings.Fields(string(data))

		src, err := parseSockFileAddr(fields[1])
		if err != nil {
			return nil, fmt.Errorf("cannot parse src addr `%s`: %w", fields[1], err)
		}

		dst, err := parseSockFileAddr(fields[2])
		if err != nil {
			return nil, fmt.Errorf("cannot parse dst addr `%s`: %w", fields[2], err)
		}

		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("cannot parse inode `%s`: %w", fields[11], err)
		}

		result = append(result, Sock{
			Inode:  inode,
			Local:  src,
			Remote: dst,
		})
	}

	return result, nil
}

func parseSockFileAddr(rawAddr string) (netip.AddrPort, error) {
	parts := strings.SplitN(rawAddr, ":", 2)
	if len(parts) != 2 {
		return netip.AddrPort{}, fmt.Errorf("cannot parse `%s`: expected `2` parts but got `%d`",
			rawAddr, len(parts))
	}

	addrData, err := hex.DecodeString(parts[0])
	if err != nil {
		return netip.AddrPort{}, err
	}

	var addr netip.Addr

	switch len(addrData) {
	case 4:
		addr = netip.AddrFrom4([4]byte{
			addrData[3], addrData[2], addrData[1], addrData[0],
		})

	case 16:
		// The data is stored in chunks of 4 bytes ordered in big endian.
		addr = netip.AddrFrom16([16]byte{
			addrData[3], addrData[2], addrData[1], addrData[0],
			addrData[7], addrData[6], addrData[5], addrData[4],
			addrData[11], addrData[10], addrData[9], addrData[8],
			addrData[15], addrData[14], addrData[13], addrData[12],
		})

	default:
		return netip.AddrPort{}, fmt.Errorf("expected either 4 or 16 bytes for ip, but got %d", len(addrData))
	}

	portData, err := hex.DecodeString(parts[1])
	if err != nil {
		return netip.AddrPort{}, err
	}

	port := binary.BigEndian.Uint16(portData)

	return netip.AddrPortFrom(addr, port), nil
}

func parseCmdline(data []byte) []string {
	result := strings.Split(string(data), "\x00")

	// We need to cut the last element, since data will end with a NULL byte,
	// causing the last element always to be empty.
	return result[0 : len(result)-1]
}

func pidToString(pid PID) string {
	return strconv.FormatUint(uint64(pid), 10)
}

type processTreeData struct {
	PPID PID
	// StartTime is measured in ticks since host start.
	StartTime uint64
}

func getDataFromStat(data []byte) (processTreeData, error) {
	commEndIndex := bytes.Index(data, []byte{')', ' '})
	if commEndIndex < 0 {
		return processTreeData{}, ErrParseStatFileInvalidCommFormat
	}

	// According to https://man7.org/linux/man-pages/man5/proc.5.html , the PPID is the 4 field. Since we cut
	// out `comm` (2 field) we need to adjust the index. The -1 is to adjust for zero being the first elements in slices.
	adjustedPPIDIdx := 4 - 2 - 1
	adjustedStartTimeIdx := 22 - 2 - 1

	maxFields := adjustedStartTimeIdx + 1

	fields := bytes.SplitN(data[commEndIndex+2:], []byte{' '}, maxFields+1)
	if len(fields) < maxFields {
		return processTreeData{}, ErrParseStatFileNotEnoughFields
	}
	ppid, err := parsePID(string(fields[adjustedPPIDIdx]))
	if err != nil {
		return processTreeData{}, err
	}
	startTime, err := strconv.ParseUint(string(fields[adjustedStartTimeIdx]), 10, 64)
	if err != nil {
		return processTreeData{}, err
	}

	return processTreeData{
		PPID:      ppid,
		StartTime: startTime,
	}, nil
}

func numOnlyName(name string) bool {
	for _, r := range name {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}
