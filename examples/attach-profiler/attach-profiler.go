package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pyroscope-io/dotnetdiag"
	"github.com/pyroscope-io/dotnetdiag/examples/attach-profiler/api"
	"google.golang.org/protobuf/proto"
)

const (
	pyroscopePath          = "/tmp/libpyroscope.so"
	pyroscopeUUID          = "BD1A650D-AC5D-4896-B64F-D6FA25D6B26A"
	drdotnetPath           = "/tmp/libprofilers.so"
	drdotnetCpuHotpathUUID = "805A308B-061C-47F3-9B30-A485B2056E71"
	drdotnetExceptionsUUID = "805A308B-061C-47F3-9B30-F785C3186E82"
)

func clsidFromString(str string) dotnetdiag.CLSID {
	str = strings.ReplaceAll(str, "-", "")

	data, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}

	if len(data) != 16 {
		panic("invalid CLSID length")
	}

	clsid := dotnetdiag.CLSID{}
	buf := bytes.NewBuffer(data[0:8])

	if err := binary.Read(buf, binary.BigEndian, &clsid.X); err != nil {
		panic(err)
	}
	if err := binary.Read(buf, binary.BigEndian, &clsid.S1); err != nil {
		panic(err)
	}
	if err := binary.Read(buf, binary.BigEndian, &clsid.S2); err != nil {
		panic(err)
	}

	copy(clsid.C[:], data[8:16])

	return clsid

}

func main() {
	var socketPath string
	flag.StringVar(&socketPath, "socket", "", "Target socket path")
	flag.Parse()

	c := dotnetdiag.NewClient(socketPath)

	info, err := c.ProcessInfo2(nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("info: %+#v\n", info)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	//147:        let time_interval_ms = session_info.get_parameter::<u64>("time_interval_ms").unwrap();
	//148:        let duration_seconds = session_info.get_parameter::<u64>("duration_seconds").unwrap();
	//149:        let filter_suspended_threads = session_info.get_parameter::<bool>("filter_suspended_threads").unwrap();
	//150:        let caller_to_callee = session_info.get_parameter::<bool>("caller_to_callee").unwrap();
	//176:        let max_stacks = session_info.get_parameter::<u64>("max_stacks").unwrap() as usize;

	payload := &api.SessionInfo{
		Uuid:        uuid.New().String(),
		ProcessName: info.AssemblyName,
		Timestamp:   time.Now().Format(time.RFC3339),
		Profiler: &api.ProfilerInfo{
			Uuid: drdotnetCpuHotpathUUID,
			Parameters: []*api.ProfilerParameter{
				{
					Key:   "time_interval_ms",
					Type:  api.ParameterType_INT,
					Value: "10",
				},
				{
					Key:   "duration_seconds",
					Type:  api.ParameterType_INT,
					Value: "10",
				},
				{
					Key:   "filter_suspended_threads",
					Type:  api.ParameterType_BOOLEAN,
					Value: "true",
				},
				{
					Key:   "caller_to_callee",
					Type:  api.ParameterType_BOOLEAN,
					Value: "false",
				},
				{
					Key:   "max_stacks",
					Type:  api.ParameterType_INT,
					Value: "100",
				},
			},
		},
	}

	msg, err := proto.Marshal(payload)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = c.AttachProfiler(dotnetdiag.AttachProfilerPayload{
		AttachTimeout: 4000,
		ProfilerPath:  drdotnetPath,
		ProfilerGUID:  clsidFromString(drdotnetCpuHotpathUUID),
		ClientData:    msg,
	})

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
