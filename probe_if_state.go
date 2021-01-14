/*
 * Author: monkeyyang@tencent.com
 */
package main
import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"unsafe"
	"time"

	"github.com/iovisor/gobpf/elf"
)
/*
#include <linux/types.h>

struct probe_event_t {
	__u64 cpu;
	__u32 pid;
	__u32 netns;
	__u32 state;
	char comm[16]; //TASK_COMM_LEN
        char ifname[16]; //IFNAMSIZ
};

*/
import "C"
type ProbeEvent struct {
	CPU       uint64
	PID       uint32
	netns     uint32
	state     uint32
	comm	  string
        ifname	  string
}

func syscallEventToGo(data *[]byte) (event ProbeEvent) {
	eventC := (*C.struct_probe_event_t)(unsafe.Pointer(&(*data)[0]))

	event.CPU = uint64(eventC.cpu)
	event.PID = uint32(eventC.pid)
	event.netns = uint32(eventC.netns)
	event.state = uint32(eventC.state)
	event.comm = string(C.GoBytes(unsafe.Pointer(&eventC.comm), 16))
	event.ifname = string(C.GoBytes(unsafe.Pointer(&eventC.ifname), 16))

	return
}

func main() {
	module := elf.NewModule("./probe_if_state.o")
	err := module.Load(nil)
	fmt.Printf("%s\n", string(module.Log()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load program: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := module.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to close program: %v\n", err)
		}
	}()

	fmt.Println("Loaded BPF program")

	netnsToWatchMap := module.Map("netns_to_watch")
	if netnsToWatchMap == nil {
		fmt.Fprintf(os.Stderr, "Failed to load 'netns_to_watch' map\n")
		os.Exit(1)
	}

	if err := module.EnableKprobe("kprobe/dev_change_flags", 0); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to enable kprobe dev_change_flags %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Enabled kprobe dev_change_flags")

	var one uint32 = 1
	for _, netnsStr := range os.Args[1:] {
		netns, err := strconv.Atoi(netnsStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to convert %q to int: %v\n", netnsStr, err)
			os.Exit(1)
		}
		if err := module.UpdateElement(netnsToWatchMap, unsafe.Pointer(&netns), unsafe.Pointer(&one), 0); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to add netns %d to watch list: %v\n", netns, err)
			os.Exit(1)
		}
		fmt.Printf("Watching netns %d ...\n", netns)
	}

	eventChan := make(chan []byte)
	lostChan := make(chan uint64)

	perfMap, err := elf.InitPerfMap(module, "probe_event", eventChan, lostChan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize 'probe_event' perf map: %v\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	perfMap.PollStart()

L:
	for {
		select {
		case <-sig:
			perfMap.PollStop()
			break L
		case data, ok := <-eventChan:
			if !ok {
				continue
			}
			event := syscallEventToGo(&data)
			stateChangeMsg  := []string {
				"down/up not change",
				"up2down",
				"down2up",
			};
			fmt.Printf("%s cpu:%d pid:%v comm:%s interface:%s netns:%d state:%s\n", time.Now().Format("2006-01-02 15:04:05"),
				event.CPU, event.PID, event.comm, event.ifname, event.netns, stateChangeMsg[event.state])
		case lost, ok := <-lostChan:
			if !ok {
				continue
			}
			fmt.Printf("ERR: lost %d events\n", lost)
		}

	}
}
