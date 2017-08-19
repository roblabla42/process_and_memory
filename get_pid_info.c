#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/fs_struct.h>
#include <linux/anon_inodes.h>
#include <asm/page.h>
#include <asm/mman.h>

struct pid_info {
	int pid;
	int state;
	void __user *stack;
	unsigned long long age;
	// TODO: Figure out a good maxlen for children
	int children[128];
	int parent_pid;
	char path[PATH_MAX];
	char pwd[PATH_MAX];
};

static int pid_stack_vops_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page;
	int res = 0;
	struct vm_area_struct *src_vma = vma->vm_private_data;
	unsigned long virt = src_vma->vm_start + (vmf->pgoff * PAGE_SIZE);
	int locked = 1;
	/********pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;*/

	printk(KERN_INFO "Faulting at page offset %lu(full addr %lu)", vmf->pgoff, virt);
	if (src_vma->vm_mm != current->mm)
		down_read(&src_vma->vm_mm->mmap_sem);
	/*printk(KERN_INFO "Getting pgd");
	pgd = pgd_offset(src_vma->vm_mm, virt);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return VM_FAULT_SIGBUS;
	printk(KERN_INFO "Getting pud from pgd %lu", pgd_val(*pgd));
	pud = pud_offset(pgd, virt);
	if (pud_none(*pud) || pud_bad(*pud))
		return VM_FAULT_SIGBUS;
	printk(KERN_INFO "Getting pmd from pud %lu", pud_val(*pud));
	pmd = pmd_offset(pud, virt);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return VM_FAULT_SIGBUS;
	printk(KERN_INFO "Getting pte from pmd %lu", pmd_val(*pmd));
	pte = pte_offset_map(pmd, virt);
	if (!pte)
		return VM_FAULT_SIGBUS;
	// TODO: Sometimes pte_val(*pte) returns 0. It seems I shouldn't
	// use them in this case.
	printk(KERN_INFO "Getting page from pte %lu", pte_val(*pte));
	if (!(page = pte_page(*pte)))
		return VM_FAULT_SIGBUS;
	printk(KERN_INFO "Releasing src_vma lock");
	if (src_vma->vm_mm != current->mm && locked)
		up_read(&src_vma->vm_mm->mmap_sem);
	printk(KERN_INFO "Increasing page refcount");
	get_page(page);
	printk(KERN_INFO "Returning page %p", page);
	vmf->page = page;*/
	// back to get_user_pages, as that's what access_vm does
	printk(KERN_INFO "Setting pages from %p to %p", src_vma->vm_mm, vma->vm_mm);
	printk(KERN_INFO "Get user pages");
	res = get_user_pages_remote(NULL, src_vma->vm_mm, virt, 1, FOLL_FORCE, &page, NULL, &locked);
	if (res > 0) {
		printk(KERN_INFO "Setting page to vmf");
		get_page(page);
		vmf->page = page;
		res = 0;
	} else if (res == 0) {
		printk(KERN_INFO "We failed !");
		res = VM_FAULT_SIGBUS;
	}
	// What happens if I (conveniently) forget to unlock ?
	if (src_vma->vm_mm != current->mm && locked)
		up_read(&src_vma->vm_mm->mmap_sem);
	return res;
}

/*static void pid_stack_vops_close(struct vm_area_struct *area) {
	struct vm_area_struct *src_vma = vma->vm_private_data.vma;
	int locked = vma->vm_private_data.locked;
	if (src_vma->vm_mm != current->mm && locked) {
		up_read(&src_vma->vm_mm->mmap_sem);
	}
}*/

static const struct vm_operations_struct pid_stack_vops = {
	.fault	= pid_stack_vops_fault,
	//.close	= pid_stack_vops_close,
};


/*
 * There are really two ways to handle mmap.
 * Either we remap everything at mmap time, or we override the vma's
 * vm_ops->fault, and handle the page faults.
 *
 * I think there's a bit of confusion here betwen task->stack and what I usually
 * call the stack. Could it be that the kernel has its own per-process stack ?
 */
static int pid_stack_fops_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct task_struct *src_tsk = filp->private_data;
	struct vm_area_struct *src_vma;
	int res = 0;

	// TODO: Better error value ?
	if (vma->vm_flags & VM_WRITE)
		return -EINVAL;
	if (!src_tsk->mm || (src_vma = find_vma(src_tsk->mm, src_tsk->mm->start_stack)) == NULL)
		return -EINVAL;
	/*vma->vm_ops = &pid_stack_vops;
	vma->vm_private_data = src_vma;
	return res;*/

	/*
	stmp = src_vma->vm_start + vma->vm_pgoff;
	dtmp = vma->vm_start;
	while (dtmp < vma->vm_end)
	{
		// get pte_t. We know that follow_pte_t fails. How does get_user_pages do it ?
		dtmp += PAGE_SIZE;
		stmp += PAGE_SIZE;
	}*/

	nr_pages = (src_vma->vm_end - src_vma->vm_start) / PAGE_SIZE;
	pages = kmalloc(sizeof(struct page*) * nr_pages, GFP_KERNEL);
	printk(KERN_INFO "Getting user pages!");
	// TODO: This deadlocks when src_vma->vm_mm == current->mm. I should probably
	// get to the bottom of this
	if (src_vma->vm_mm != current->mm)
		down_read(&src_vma->vm_mm->mmap_sem);
	if ((nr_pages = get_user_pages_remote(NULL, src_vma->vm_mm, src_vma->vm_start, nr_pages, 0, pages, NULL, &locked)) < 0) {
        res = -nr_pages;
		goto free;
    }
	if (src_vma->vm_mm != current->mm && locked)
		up_read(&src_vma->vm_mm->mmap_sem);
	for (i = 0; i < nr_pages; i++)
	{
		printk(KERN_INFO "Remapping !");
		if ((res = vm_insert_page(vma, vma->vm_start + i * PAGE_SIZE, pages[i])) != 0)
			printk(KERN_INFO "Got an error remapping %d", i);
		res = 0;
		i++;
	}
release:
	for (i = 0; i < nr_pages; i++)
		put_page(pages[i]);
free:
	kfree(pages);
	printk(KERN_INFO "Done !");
	return res;
}

const struct file_operations pid_stack_fops = {
	.owner = THIS_MODULE,
	.mmap = pid_stack_fops_mmap,
};

static int cpypath(char *dest, const struct path *path, size_t len)
{
	char *res = d_path(path, dest, len);
	if (IS_ERR(res))
		return PTR_ERR(res);

	/*
	 * d_path may put bytes anywhere inside the buffer. We're going to move
	 * those bytes back to the beginning of our buffer.
	 */
	memmove(dest, res, len - (res - dest));
	return 0;
}

// TODO: Take care of the damned semaphores.
// TODO: Take care of error handling
SYSCALL_DEFINE2(get_pid_info, struct pid_info __user *, ref, int, pid)
{
	struct task_struct *task;
	struct task_struct *child_task;
	struct file *stack_file;
	struct pid_info *info = NULL;
	struct list_head *list;
	int i = 0;
	int res = 0;

	/*
	 * Accessing find_task_by_vpid requires rcu read lock.
	 */
	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (task == NULL)
		goto err_no_task;

	/*
	 * Increment RC count for task struct
	 * TODO: Synchronization ? there is a task_lock() function. Should I ?
	 * It seems to lock fs, which I use. So I guess the answer is yes.
	 */
	get_task_struct(task);
	rcu_read_unlock();

	/*
	 * TODO: Do I really need this allocation ?
	 */
	info = kmalloc(sizeof(struct pid_info), GFP_KERNEL);
	if (info == NULL) {
		res = -ENOMEM;
		goto cleanup;
	}
	info->pid = task_pid_vnr(task);
	info->state = task->state;
	info->age = ktime_get_ns() - task->start_time;
	/*
	 * Here, task_pid_vnr takes care of the synchronization through RCU lock.
	 *
	 * We don't need to increment/decrement RC because the reference we have
	 * is bound to the "task" struct we're currently handling. Since this
	 * struct cannot be destroyed (we "got" it), the parent cannot be destroyed
	 * either.
	 * UPDATE 16 MAY : ?? Verify this assumption is true ! While my guts are
	 * telling me this is probably OK, I would like to be sure
	 *
	 * A note on parent/real_parent. Parent is the recipient of wait4 calls,
	 * whereas real_parent is the task that created the current task. Hence,
	 * what we want is real_parent.
	 */
	info->parent_pid = task_pid_vnr(task->real_parent);
	/*
	 * TODO: map this pointer to current's address space.
	 *
	 * Memory mapping already exists for two basic use-cases. The first one,
	 * obviously, is IPC : you let two processes access the same memory for
	 * communication purposes. The second one is debugging.
	 *
	 * Let's look at MMAP first. MMAP has two basic modes of operations :
	 * 1. Anonymous allocation. This is the basic call behind malloc.
	 * 2. File mapping. In this mode, you give mmap a file, and it will map it
	 * to memory. Accessing this memory will modify the file on disk.
	 *
	 * There is no obvious way to use MMAP to map *existing memory* (the stack)
	 * to our address space.
	 *
	 * Let's look at debugging calls. There are two system calls of interest
	 * here : The first one is ptrace, and the second one is process_vm_readv.
	 * I invite the reader to look at the ptrace man, and
	 * http://blog.tartanllama.xyz/c++/2017/03/31/writing-a-linux-debugger-registers/
	 * Those are very instructive reads.
	 *
	 * It turns out ptrace has commands to read memory one word at a time. It's
	 * nice, but not suitable for our purposes. However, the link I gave you
	 * gives us a very interesting hint : /proc/<pid>/mem.
	 *
	 * After a bit of guesswork, I managed to find the name of the variable
	 * driving this file : proc_mem_operations. Unfortunately, looking at the
	 * definition, it does not seem to support the `mmap` operation.
	 *
	 * Aftersome spelunking, I found out it did support it a looong time ago !
	 *
	 * https://git.kernel.org/pub/scm/linux/kernel/git/history/history.git/tree/fs/proc/mem.c?h=2.0.40#n217
	 *
	 * It seems like it got removed for security reasons or something. Meh. It
	 * also has a reliability warning on top of it.
	 *
	 * We're going to have to fiddle with the process' memory table. Fuuuun.
	 *
	 * Some googling gives us some hints about what to look for. Paging seems
	 * to play a big part in how linux handles memory. Here's a cool link about
	 * paging in x86 :
	 * http://www.cirosantilli.com/x86-paging/
	 *
	 * And here's a link about how paging is used in linux :
	 * https://www.kernel.org/doc/gorman/html/understand/understand006.html
	 *
	 * So what we have to do is find the struct page associated with the stack,
	 * and set it to a PTE in the process memory.
	 *
	 * http://duartes.org/gustavo/blog/post/how-the-kernel-manages-your-memory/
	 *
	 * Now I think I have more or less all the things I need to understand my task
	 *
	 * The goal is to map all the pages of memory between task->mm->start_stack
	 * and task->mm->end_stack to the current task.
	 *
	 * Now, the best way to do this would be to create a "fake" pid proc
	 * (basically taking the old mmap impl, and updating it).
	 */

	// TODO: Error handling down there
	// get stack page
	stack_file = anon_inode_getfile("pidstack", &pid_stack_fops, task, O_RDONLY);
	// TODO: Figure out the correct length.
	info->stack = (void*)vm_mmap(stack_file, 0, 0x21000, PROT_READ, MAP_PRIVATE, 0);
	if (IS_ERR(info->stack)) {
		info->stack = NULL;
		//res = PTR_ERR(info->stack);
		//goto cleanup;
	}
	list_for_each(list, &task->children) {
		if (i >= 127)
			break;

		child_task = list_entry(list, struct task_struct, sibling);
		/*
		 * RCU/RC follows a similar reasoning to the parent.
		 */
		info->children[i] = task_pid_vnr(child_task);
		if (info->children[i])
			i++;
	}
	info->children[i] = 0;

	/*
	 * Again for Rc, we're handling this through the task reference.
	 * For synchronization, task->fs uses a spinlock. We'll grab that.
	 */
	spin_lock(&task->fs->lock);
	// TODO: Error handling
	res = cpypath(info->path, &task->fs->root, PATH_MAX) ||
		cpypath(info->pwd, &task->fs->pwd, PATH_MAX);
	spin_unlock(&task->fs->lock);
	if (res)
		goto cleanup;

	// TODO: Transform res into something more reasonable.
	res = copy_to_user(ref, info, sizeof(struct pid_info));
cleanup:
	kfree(info);
	/*
	 * Decrement task RC count.
	 */
	put_task_struct(task);
	return res;
err_no_task:
	rcu_read_unlock();
	return -ESRCH;
}
