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

extern pid_t sigmonitor_pid;

char *get_cmdline_for_current(void);

int get_cmdline(struct task_struct *task, char *buffer, int buflen);

void describe_task(struct task_struct *t, bool is_atomic);

void dump_task_tree(struct task_struct *t);

int install_jprobe(struct jprobe *jp);

void uninstall_jprobe(struct jprobe *jp);

struct task_struct *find_task_by_pid(pid_t pid);

bool is_sig_intresting(int sig);

bool is_dest_pid_intresting(pid_t pid);

bool is_dest_task_intresting(struct task_struct *dst);

bool is_siginfo_from_kernel(struct siginfo *info);

void reset_sigmonitor_pid(void);

static inline int is_si_special(const struct siginfo *info)
{
	return info <= SEND_SIG_FORCED;
}


#define _put_task_struct(tsk) do { atomic_dec_and_test(&(tsk)->usage); } while(0)
