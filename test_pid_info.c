#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>

struct pid_info {
	int pid;
	int state;
	size_t stacklen;
	char *stack;
	unsigned long long age;
	// TODO: Figure out a good maxlen for children
	int children[128];
	int parent_pid;
	char path[PATH_MAX];
	char pwd[PATH_MAX];
};

long	get_pid_info(struct pid_info *ret, int pid)
{
	return syscall(332, ret, pid);
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

int main(int argc, char **argv)
{
	char name[1024];
	struct pid_info ret;
	int pid;
	int i;

	if (argc > 1)
		pid = atoi(argv[1]);
	else
		pid = getpid();

	// TODO: Check errno, use perror, etc...
	if (get_pid_info(&ret, pid)) {
		perror("get_pid_info");
		return 1;
	}
	printf("pid = %d\n", ret.pid);
	printf("state = %s\n", str_from_task_state(ret.state));
	printf("age = %lluns\n", ret.age);
	printf("parent_pid = %s(%d)\n", get_process_name_by_pid(ret.parent_pid, name), ret.parent_pid);
	printf("path = %.*s\n", PATH_MAX, ret.path);
	printf("pwd = %.*s\n", PATH_MAX, ret.pwd);
	printf("children:\n");
	i = 0;
	while (i < 128 && ret.children[i] != 0) {
		printf("- %s(%d)\n", get_process_name_by_pid(ret.children[i], name), ret.children[i]);
		i++;
	}
	printf("stackptr = %p\n", ret.stack); // TODO: Hex dump - How do we know the end ?
	if (ret.stack)
		hexDump("stack", ret.stack, 0x21000);
		hexDump("stack", ret.stack, ret.stacklen);
	return 0;
}
