#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/stacktrace.h>
#include <linux/signal.h>
#include <linux/signalfd.h>
#include <asm/siginfo.h>

#include "sig_monitor_base.h"


void dump_sighand(struct sighand_struct *sighand)
{
	int i;
	int n = ARRAY_SIZE(sighand->action);
	printk(KERN_INFO"NSIG=%d\n", n);
	for (i = 0; i < n; i++) {
		struct sigaction *sa = &sighand->action[i].sa;
		printk(KERN_INFO"SIG %d: sa_handler=%p, sa_flags=0x%lx, mask=0x%lx\n",
				i + 1, sa->sa_handler, sa->sa_flags, sa->sa_mask.sig[0]);
	}
}

int init_module(void)
{
	struct task_struct *t;

	t = find_task_by_pid(sigmonitor_pid);
	if (!t)
		return 0;

	dump_sighand(t->sighand);

	_put_task_struct(t);
	return 0;
}

void cleanup_module(void)
{

}

MODULE_LICENSE("GPL");

