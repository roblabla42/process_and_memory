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
	size_t stacklen;
	char __user *stack;
	unsigned long long age;
	size_t childrenlen;
	int __user *children;
	int parent_pid;
	char path[PATH_MAX];
	char pwd[PATH_MAX];
};

/*
 * There are really two ways to handle mmap.
 * Either we remap everything at mmap time, or we override the vma's
 * vm_ops->fault, and handle the page faults. We're going with the former as
 * it's easier
 */
static int pid_stack_fops_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct task_struct *src_tsk = filp->private_data;
	int res = 0;
	int i = 0;
	struct page *page;

	// TODO: Better error value ?
	if (vma->vm_flags & VM_WRITE)
		return -EINVAL;
	if (src_tsk->stack == NULL)
		return -EINVAL;

	/* vm_insert_page takes care of get_page */
#ifdef CONFIG_VMAP_STACK
	for (i = 0; i < THREAD_SIZE && i < (vma->vm_end - vma->vm_start); i += PAGE_SIZE) {
		if ((page = vmalloc_to_page(src_tsk->stack + i)) == NULL) {
			printk(KERN_ERR "Attempted to remap null page !");
			res = -EINVAL;
			goto end;
		}
		if ((res = vm_insert_page(vma, vma->vm_start + i, page)) < 0) {
			printk(KERN_ERR "Failed to insert page %ld", i / PAGE_SIZE);
			goto end;
		}
	}
#else
	page = vma->vm_start;
	if ((res = vm_insert_page(vma, vma->vm_start, page)) < 0) {
		printk(KERN_ERR "Failed to insert page");
		goto end;
	}
#endif
end:
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
		goto cleanup2;
	}
	if (copy_from_user(info, ref, sizeof(struct pid_info)) != 0) {
		res = -EINVAL;
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

	// TODO: Error handling down there
	// get stack page
	stack_file = anon_inode_getfile("pidstack", &pid_stack_fops, task, O_RDONLY);
	info->stacklen = THREAD_SIZE;
	info->stack = (void*)vm_mmap(stack_file, 0, THREAD_SIZE, PROT_READ, MAP_PRIVATE, 0);
	if (IS_ERR(info->stack)) {
		res = PTR_ERR(info->stack);
		goto cleanup;
	}

	/* It's impossible (or at least hard) to allocate memory for userspace from
	 * kernelspace. So instead, we ask the user to provide a userspace-allocated
	 * array for us to put the pid list into.
	 */
	list_for_each(list, &task->children) {
		if (i >= info->childrenlen)
			break;

		child_task = list_entry(list, struct task_struct, sibling);
		/*
		 * RCU/RC follows a similar reasoning to the parent.
		 */
		pid = task_pid_vnr(child_task);
		if (copy_to_user(info->children + i, &pid, sizeof(int)) != 0) {
			res = -EINVAL;
			goto cleanup;
		}
		i++;
	}
	info->childrenlen = i;

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
cleanup2:
	/*
	 * Decrement task RC count.
	 */
	put_task_struct(task);
	return res;
err_no_task:
	rcu_read_unlock();
	return -ESRCH;
}
