#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>

/* All the fields are out (meaning they can be uninitialized when sent to the
 * kernel), except for children/childrenlen. The user should initialize it to an
 * array of their choice, and give the pointer to the kernelspace along with its
 * size.
 *
 * The kernel will then fill the array with the pid list, and adjust childrenlen
 * accordingly. If childrenlen is the same before and after the syscall, you
 * probably want to make the array bigger and call the syscall again.
 */
struct pid_info {
	int pid;
	int state;
	size_t stacklen;
	char *stack;
	unsigned long long age;
	size_t childrenlen;
	int *children;
	int parent_pid;
	char path[PATH_MAX];
	char pwd[PATH_MAX];
};

long	get_pid_info(struct pid_info *ret, int pid)
{
	return syscall(350, ret, pid);
}

const char *str_from_task_state(long long state)
{
	return state == -1 ? "unrunnable" :
		state == 0 ? "runnable" :
		"stopped";
}

const char* get_process_name_by_pid(const int pid, char name[1024])
{
	if(name){
		sprintf(name, "/proc/%d/cmdline",pid);
		FILE* f = fopen(name,"r");
		if(f){
			size_t size;
			size = fread(name, sizeof(char), 1024, f);
			if(size>0){
				if('\n'==name[size-1])
					name[size-1]='\0';
			} else {
				name[0] = '\0';
			}
			fclose(f);
		} else {
			name[0] = '\0';
		}
	}
	return name;
}

void hexDump (char *desc, void *addr, int len) {
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		printf ("%s:\n", desc);

	if (len == 0) {
		printf("  ZERO LENGTH\n");
		return;
	}
	if (len < 0) {
		printf("  NEGATIVE LENGTH: %i\n",len);
		return;
	}
	// TODO log10 the len to get the pad amount

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf ("  %s\n", buff);

			// Output the offset.
			printf ("%06x  ", i);
		}

		// Separate every 2 hex codes with a space
		if ((i % 2) == 0 && (i % 16) != 0) {
			printf (" ");
		}

		// Now the hex code for the specific character.
		printf ("%02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf ("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf ("  %s\n", buff);
}

void space_pad(int depth) {
	while (depth--) {
		putchar(' ');
	}
}

int process_pid(int pid, int process_children, int process_parent, int process_stack, int depth) {
	char name[1024];
	struct pid_info ret = {0};
	int i = 64;

	do {
		// Free on null is a NOOP
		free(ret.children);
		ret.childrenlen = i = i * 2;
		ret.children = malloc(sizeof(int) * i);
		if (ret.children == NULL) {
			perror("malloc");
			return 1;
		}
		if (get_pid_info(&ret, pid)) {
			perror("get_pid_info");
			printf("Failed on %d\n", pid);
			return 1;
		}
	} while (ret.childrenlen == i);
	space_pad(depth);
	printf("- %s(%d) - %s, uptime: %llums, path: %.*s, pwd: %.*s\n",
		get_process_name_by_pid(ret.pid, name), ret.pid,
		str_from_task_state(ret.state), ret.age / 1000000, PATH_MAX, ret.path,
		PATH_MAX, ret.pwd);
	if (process_stack) {
		hexDump("stack", ret.stack, ret.stacklen);
	}
	if (process_parent && ret.parent_pid != 0) {
		space_pad(depth);
		printf("  parent:\n");
		if (process_pid(ret.parent_pid, 0, 0, 0, depth + 4))
			return (1);
	}
	if (process_children && ret.childrenlen != 0) {
		space_pad(depth);
		printf("  children:\n");
		i = 0;
		while (i < ret.childrenlen) {
			if (process_pid(ret.children[i], 1, 0, 0, depth + 4))
				return (1);
			i++;
		}
	}
	free(ret.children);
	return (0);
}

int main(int argc, char **argv)
{
	char name[1024];
	int pid;
	int i;

	if (argc > 1)
		pid = atoi(argv[1]);
	else
		pid = getpid();
	process_pid(pid, 1, 1, 1, 0);
	// TODO: Check errno, use perror, etc...
	return 0;
}
