#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/stacktrace.h>

#include "sig_monitor_base.h"


	static void
jprobe_sys_kill(pid_t pid, int sig)
{
	struct task_struct *from, *to;

	rcu_read_lock();
	if (!is_sig_intresting(sig))
		goto ret;


	from = current;
	to = find_task_by_pid(pid);

	if (!to)
		goto ret;

	if (!is_dest_pid_intresting(pid) &&
			!is_dest_task_intresting(to)) {
		_put_task_struct(to);
		goto ret;
	}

	printk(KERN_INFO"===========sys_kill==========\n"
			"user:%d process:%d[%s] send SIG %d to %d[%s]\n",
			current_uid(), from->pid, from->comm, sig, to->pid, to->comm);
	dump_task_tree(from);
	dump_task_tree(to);
	_put_task_struct(to);
	//dump_stack();
	printk(KERN_INFO"===========sys_kill==========\n");

ret:
	rcu_read_unlock();
	jprobe_return();
	return;
}


	static void
jprobe_send_signal(int sig, struct siginfo *info, struct task_struct *t,
		int group, int from_ancestor_ns)
{
	char *cmdline;
	rcu_read_lock();

	//if (!is_siginfo_from_kernel(info))
	//	goto ret;

	if (!is_sig_intresting(sig))
		goto ret;

	if (!t)
		goto ret;

	get_task_struct(t); 

	if (!is_dest_pid_intresting(t->pid) &&
			!is_dest_task_intresting(t)) {
		_put_task_struct(t);
		goto ret;
	}

	printk(KERN_INFO"==========send_signal===========\n"
			"SIG %d to %d[%s], tgid=%d, info=0x%lx\n",
			sig, t->pid, t->comm, t->tgid,
			is_si_special(info) ? (unsigned long)info : info->si_code);

	dump_task_tree(t);
	_put_task_struct(t);

	// current cmdline
	cmdline = get_cmdline_for_current();
	if (cmdline) {
		printk(KERN_INFO"current (%d, tgid=%d) cmd:\n",
				current->pid, current->tgid);
		printk(KERN_INFO"%s\n", cmdline);
	}
	kfree(cmdline);
	dump_stack(); 
	printk(KERN_INFO"==========send_signal===========\n");

ret:
	rcu_read_unlock();
	jprobe_return();
	return;
}


static struct jprobe jp_sys_kill = {
	.kp = {
		.symbol_name = "sys_kill",
	},
	.entry = (kprobe_opcode_t *)jprobe_sys_kill,
};

static struct jprobe jp_send_signal = {
	.kp = {
		.symbol_name = "__send_signal",
	},
	.entry = (kprobe_opcode_t *)jprobe_send_signal,
};



int init_module(void)
{
	int ret = 0;
	ret = install_jprobe(&jp_sys_kill);
	ret += install_jprobe(&jp_send_signal);
	return ret;
}

void cleanup_module(void)
{
	uninstall_jprobe(&jp_sys_kill);
	uninstall_jprobe(&jp_send_signal);
}

MODULE_LICENSE("GPL");

