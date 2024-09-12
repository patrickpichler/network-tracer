package proc

import (
	"fmt"
	"net/netip"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

func TestParseSockFileAddr(t *testing.T) {
	type testCase struct {
		title          string
		input          string
		expectErr      bool
		expectedOutput netip.AddrPort
	}

	testCases := []testCase{
		{
			title:          "ipv4",
			input:          "0100007F:22BA",
			expectedOutput: netip.MustParseAddrPort("127.0.0.1:8890"),
		},
		{
			title:          "ipv6",
			input:          "650BAEFD83CA9085FF5555504035EDFE:22BA",
			expectedOutput: netip.MustParseAddrPort("[fdae:b65:8590:ca83:5055:55ff:feed:3540]:8890"),
		},
		{
			title:     "invalid",
			input:     "asdf:22BA",
			expectErr: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			r := require.New(t)

			result, err := parseSockFileAddr(test.input)
			if test.expectErr {
				r.Error(err)
				return
			}

			r.NoError(err)
			r.Equal(test.expectedOutput, result)
		})
	}
}

func TestParseSockFile(t *testing.T) {
	type testCase struct {
		title          string
		input          string
		expectErr      bool
		expectedOutput []Sock
	}

	testCases := []testCase{
		{
			title: "empty",
			input: "sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     ",
		},
		{
			title: "ipv4",
			input: `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
3: 0F05A8C0:8AF0 0E1B4212:01BB 08 00000000:00000001 00:00000000 00000000   105        0 290392 1 0000000000000000 21 4 24 10 -1
4: 0F05A8C0:0016 0205A8C0:6E12 01 00000000:00000000 02:00004A95 00000000     0        0 62096 3 0000000000000000 20 4 31 10 34
5: 0F05A8C0:C24E 24BE7DB9:0050 08 00000000:00000001 00:00000000 00000000   105        0 291144 1 0000000000000000 24 4 0 10 -1`,
			expectedOutput: []Sock{
				{
					Inode:  290392,
					Local:  netip.MustParseAddrPort("192.168.5.15:35568"),
					Remote: netip.MustParseAddrPort("18.66.27.14:443"),
				},
				{
					Inode:  62096,
					Local:  netip.MustParseAddrPort("192.168.5.15:22"),
					Remote: netip.MustParseAddrPort("192.168.5.2:28178"),
				},
				{
					Inode:  291144,
					Local:  netip.MustParseAddrPort("192.168.5.15:49742"),
					Remote: netip.MustParseAddrPort("185.125.190.36:80"),
				},
			},
		},
		{
			title: "ipv6",
			input: `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 650BAEFD83CA9085FF5555504035EDFE:22BA 650BAEFD83CA9085FF5555504035EDFE:22EA 0A 00000000:00000000 00:00000000 00000000   501        0 606918 1 0000000000000000 100 0 0 10 0`,
			expectedOutput: []Sock{
				{
					Inode:  606918,
					Local:  netip.MustParseAddrPort("[fdae:b65:8590:ca83:5055:55ff:feed:3540]:8890"),
					Remote: netip.MustParseAddrPort("[fdae:b65:8590:ca83:5055:55ff:feed:3540]:8938"),
				},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			r := require.New(t)

			fs := fstest.MapFS{
				"tcp": &fstest.MapFile{
					Data: []byte(test.input),
				},
			}

			file, err := fs.Open("tcp")
			r.NoError(err)

			result, err := parseSocksFile(file)
			if test.expectErr {
				r.Error(err)
				return
			}

			r.EqualValues(test.expectedOutput, result)
		})
	}
}

func TestRandom(t *testing.T) {
	r := require.New(t)

	processes, err := New().SnapshotProcessTree(1)
	r.NoError(err)

	for _, p := range processes {
		fmt.Println(p.PID, p.Args, p.Socks)
	}
}
