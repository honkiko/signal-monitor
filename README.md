signal-monitor
--------------

Sometimes processes exit without any clue. No coredump, no revealing log. How to catch the murder?

### print-fatal-signals

"echo 1 > /proc/sys/kernel/print-fatal-signals" could record fatal signals, but:
- only signals generated from kernel are recorded
- no way to filter signals sent to specific process
- no way to filter specific signals. In fact, kernel is generating tons of SIGSEGV

### TraceEvent

kernel TraceEvent is more flexible. 3 events are related to signals:
- sched:sched_signal_send
- syscalls:sys_enter_kill
- syscalls:sys_exit_kill
You can do
```
echo "(sig == 15 || sig == 9) && pid == 100" > /sys/kernel/debug/tracing/events/sched/sched_signal_send/filter
echo 1 > /sys/kernel/debug/tracing/events/sched/sched_signal_send/enable
```
This looks good but usually the victim process is composed of many threads, and it's threads are terminating/creating. It doesn't work to add pids of all it's threads to the filter, because some of the threads will be destroyed and some threads with new pid will be created later.

### signal-monitor

signal-monitor is a loadable Linux kernel module to catch the murder in such case.

You build it, load it into kernel, tell it via /sys/kernel/debug/sigmonitor_pid which process you want to monitor, and via /sys/kernel/debug/sigmonitor_mask which signals is suspect. If this process exits again, all signals in sigmonitor_mask sent to this process and it's threads will be recored in dmesg, together with the source of signals.


### Usage

1. Edit Makefile to make "KDIR" point to the kernel building dir
2. make
3. copy *.ko to target machine
4. insmod sig_monitor_base.ko; insmod sig_monitor.ko
5. echo xxx > /sys/kernel/debug/sigmonitor_pid
6. (optional) echo 0x00000200 > /sys/kernel/debug/sigmonitor_mask


Two virtual files are exported via debugfs:
- sigmonitor_pid
- sigmonitor_mask

Make sure debugfs is mounted(usually at /sys/kernel/debug). If not, please mount it mannually:
	mount -t debugfs debugfs /sys/kernel/debug

sigmonitor_pid is a 32-bits integer presenting the pid of which process you are interesting.

sigmonitor_mask is a 32-bits interger presenting the set of signals in interesting. The first bit presents signal 1(SIGHUP), 2nd bit presents signal 2(SIGINT), ...etc. You may run "kill -l" to see the signal number and name mapping.

### Output

The matching signal events are logged in kernel ring buffer. Check it by "dmesg" or "cat /var/log/messages".
Infomation that is recorded:
- signal number
- pid, command line, and process tree of destination process/thread
- pid, command line, and process tree of source process/thread (if this signal is sent by a user process)
