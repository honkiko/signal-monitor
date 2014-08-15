#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/stacktrace.h>
#include <asm/siginfo.h>

#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/module.h>
#include <linux/delayacct.h>
#include <linux/init.h>
#include <linux/writeback.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/elf.h>

#include <asm/io.h>
#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/debugfs.h>
#include <linux/fs.h>

#include "sig_monitor_base.h"

char *get_cmdline_for_current()
{
	struct mm_struct *mm;
	char *buf;
	struct task_struct *task;
	int len;

	task = current;
	//mm = get_task_mm(task);

	if (!task->mm || (task->flags & PF_KTHREAD))
		return "wrong-mm";

	mm = task->mm;
	atomic_inc(&mm->mm_users);

	if (!mm->arg_end) {
		buf = "wrong-mm-arg-end";
		goto out_mm;
	}
	len = mm->arg_end - mm->arg_start;

	if (len > PAGE_SIZE)
		len = PAGE_SIZE;

	buf = kzalloc(len, GFP_ATOMIC);
	if (!buf)
		goto out_mm;

	len = copy_from_user(buf, (void *)mm->arg_start, len);

out_mm:
	//mmput(mm);
	atomic_dec_and_test(&mm->mm_users);
	return buf;
}
EXPORT_SYMBOL_GPL(get_cmdline_for_current);

struct task_struct *find_task_by_pid(pid_t pid)
{
	struct task_struct *t;
	struct pid *p;
	rcu_read_lock();
	p = find_vpid(pid);
	if (!p) {
		rcu_read_unlock();
		return NULL;
	}

	t = pid_task(p, PIDTYPE_PID);
	get_task_struct(t);
	rcu_read_unlock();
	return t;
}
EXPORT_SYMBOL_GPL(find_task_by_pid);

void describe_task(struct task_struct *t, bool is_atomic)
{
	char comm[TASK_COMM_LEN + 1];
	struct timespec now;

	memset(comm, 0, sizeof(comm));

	spin_lock(&t->alloc_lock);
	strncpy(comm, t->comm, sizeof(t->comm));
	spin_unlock(&t->alloc_lock);
	//get_task_comm(comm, t);


	do_posix_clock_monotonic_gettime(&now);
	printk(KERN_INFO"    pid=%d[%s],tgid=%d, start time=%ld sec, %ld nsec\n",
			t->pid, comm, t->tgid,
			now.tv_sec - t->start_time.tv_sec, now.tv_nsec - t->start_time.tv_nsec);
	//task_unlock(t);
	//printk(KERN_INFO"    %s\n", buff);
	//if (buff != cmdline)
	//	kfree(buff);
}
EXPORT_SYMBOL_GPL(describe_task);

void dump_task_tree(struct task_struct *t)
{
	bool is_atomic;
	struct task_struct *p = t;

	if (!t)
		return;

	is_atomic = preempt_count() || irqs_disabled(); 
	printk(KERN_INFO"Task Tree of %d = {\n", t->pid);
	rcu_read_lock();
	while (p && p->pid > 1) {
		describe_task(p, is_atomic);
		if (p->group_leader != p)
			p = p->group_leader;
		else if (p->real_parent != p)
			p = p->real_parent;
		else if (p->parent != p)
			p = p->parent;
		else
			break;
	}
	rcu_read_unlock();
	printk(KERN_INFO"} // task tree\n");
}
EXPORT_SYMBOL_GPL(dump_task_tree);

int install_jprobe(struct jprobe *jp)
{
	int ret;
	if ((ret = register_jprobe(jp)) <0) {
		printk("register_jprobe %s failed, returned %d\n", 
				jp->kp.symbol_name, ret);
		return ret;
	}
	printk("installed jprobe at %s@%p, handler addr %p\n",
			jp->kp.symbol_name, jp->kp.addr, jp->entry);
	return 0;
}
EXPORT_SYMBOL_GPL(install_jprobe);

void uninstall_jprobe(struct jprobe *jp)
{
	unregister_jprobe(jp);
	printk("jprobe %s unregistered\n", jp->kp.symbol_name);
}
EXPORT_SYMBOL_GPL(uninstall_jprobe);


#define SIGM_MASK(sig) (1 << (sig - 1))

pid_t sigmonitor_pid = 0;
EXPORT_SYMBOL_GPL(sigmonitor_pid);

static u32 sigmonitor_mask = 
SIGM_MASK(SIGHUP)    |
SIGM_MASK(SIGINT)    |
SIGM_MASK(SIGQUIT)   |
SIGM_MASK(SIGILL)    |
SIGM_MASK(SIGTRAP)   |
SIGM_MASK(SIGABRT)   |
SIGM_MASK(SIGIOT)    |
//SIGM_MASK(SIGBUS)    |
//SIGM_MASK(SIGFPE)    |
SIGM_MASK(SIGKILL)   |
SIGM_MASK(SIGUSR1)   |
//SIGM_MASK(SIGSEGV)   |
//SIGM_MASK(SIGUSR2)   |
//SIGM_MASK(SIGPIPE)   |
SIGM_MASK(SIGALRM)   |
SIGM_MASK(SIGTERM)   |
SIGM_MASK(SIGSTKFLT) |
//SIGM_MASK(SIGCHLD)   |
SIGM_MASK(SIGCONT)   |
SIGM_MASK(SIGSTOP)   |
SIGM_MASK(SIGTSTP)   |
SIGM_MASK(SIGTTIN)   |
SIGM_MASK(SIGTTOU)   |
SIGM_MASK(SIGURG)    |
SIGM_MASK(SIGXCPU)   |
SIGM_MASK(SIGXFSZ)   |
SIGM_MASK(SIGVTALRM) |
SIGM_MASK(SIGPROF)   |
SIGM_MASK(SIGWINCH)  |
SIGM_MASK(SIGIO)     |
SIGM_MASK(SIGPOLL)   ;


static struct dentry *debugfs_sigmonitor_pid;
static struct dentry *debugfs_sigmonitor_mask;

bool is_sig_intresting(int sig)
{
	// SIGSYS == 31
	if (sig > SIGSYS || sig <= 0)
		return false;

	if (sigmonitor_mask & SIGM_MASK(sig))
		return true;

	return false;
}
EXPORT_SYMBOL_GPL(is_sig_intresting);


bool is_dest_pid_intresting(pid_t pid)
{
	return (pid == sigmonitor_pid);
}
EXPORT_SYMBOL_GPL(is_dest_pid_intresting);

bool is_dest_task_intresting(struct task_struct *dst)
{
	if (!dst)
		return false;

	return (dst->pid == sigmonitor_pid ||
			dst->tgid == sigmonitor_pid);
}
EXPORT_SYMBOL_GPL(is_dest_task_intresting);

void reset_sigmonitor_pid()
{
	sigmonitor_pid = 0;
}
EXPORT_SYMBOL_GPL(reset_sigmonitor_pid);

bool is_siginfo_from_kernel(struct siginfo *info)
{
	return (info != SEND_SIG_NOINFO && (is_si_special(info) || SI_FROMKERNEL(info)));
}
EXPORT_SYMBOL_GPL(is_siginfo_from_kernel);

static int set_sigmonitor_pid(void *data, u64 val)
{
	struct task_struct *t;
	pid_t pid;

	pid = (int)val;
	printk(KERN_INFO"sigmonitor_pid set from %d to %d\n",
			sigmonitor_pid, pid);

	rcu_read_lock();
	t = find_task_by_pid(pid);
	dump_task_tree(t);
	rcu_read_unlock();

	*(u32 *)data = val;
	return 0;
}
static int set_sigmonitor_mask(void *data, u64 val)
{
	printk(KERN_INFO"sigmonitor_mask set from 0x%08x to 0x%08x\n",
			sigmonitor_mask, (u32)val);
	*(u32 *)data = val;
	return 0;
}
static int debugfs_u32_get(void *data, u64 *val)
{
	*val = *(u32 *)data;
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(fops_sigmonitor_pid, debugfs_u32_get, set_sigmonitor_pid, "%llu\n");
DEFINE_SIMPLE_ATTRIBUTE(fops_sigmonitor_mask, debugfs_u32_get, set_sigmonitor_mask, "%llu\n");

static void jprobe_do_exit(long code)
{
	struct task_struct *t;

	rcu_read_lock();

	t = current;

	if (is_dest_pid_intresting(t->pid)) {
		reset_sigmonitor_pid();
		printk(KERN_INFO"+++++ reset_sigmonitor_pid from %d+++++\n", t->pid);
		dump_task_tree(t);
		goto ret;
	}

ret:
	rcu_read_unlock();
	jprobe_return();
	return;
}


static struct jprobe jp_do_exit = {
	.kp = {
		.symbol_name = "do_exit",
	},
	.entry = (kprobe_opcode_t *)jprobe_do_exit,
};


int init_module(void)
{
	debugfs_sigmonitor_pid = debugfs_create_file("sigmonitor_pid",
			0666, NULL, &sigmonitor_pid, &fops_sigmonitor_pid);
	if (debugfs_sigmonitor_pid == NULL)
		return -1;

	debugfs_sigmonitor_mask = debugfs_create_file("sigmonitor_mask",
			0666, NULL, &sigmonitor_mask, &fops_sigmonitor_mask);
	if (debugfs_sigmonitor_mask == NULL)
		return -1;

	if (install_jprobe(&jp_do_exit) != 0)
		return -1;
	return 0; 
}

void cleanup_module(void)
{
	uninstall_jprobe(&jp_do_exit);
	debugfs_remove(debugfs_sigmonitor_pid);
	debugfs_remove(debugfs_sigmonitor_mask);
}

MODULE_LICENSE("GPL");

