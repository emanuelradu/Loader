// SPDX-License-Identifier: BSD-3-Clause
/* Radu Emanuel Ioan 336CC */
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include "exec_parser.h"

static so_exec_t *exec;
static struct sigaction old_action;
int fd;

/*
 * Verific daca pagina de la adresa care a generat page fault-ul
 * se afla in interiorul vreunui segment
 */
int find_page(char *page_addr)
{
	int i;

	for (i = 0; i < exec->segments_no; i++) {
		if ((char *)exec->segments[i].vaddr <= page_addr &&
		 page_addr <= (char *)exec->segments[i].vaddr +
		  exec->segments[i].mem_size)
			return i;
	}
	return -1;
}

/*
 * Functie ce trateaza page fault-urile intalnite in timpul
 * rularii fisierului executabil
 */
static void segv_handler(int signum, siginfo_t *info, void *context)
{
	/* Daca semnalul nu e de tip segmentation fault, apelez
	 * handlerul default
	 */
	if (signum != SIGSEGV) {
		old_action.sa_sigaction(signum, info, context);
		return;
	}
	/* Daca adresa accesata se afla deja mapata in memorie, apelez
	 * handlerul default
	 */
	if (info->si_code == SEGV_ACCERR) {
		old_action.sa_sigaction(signum, info, context);
		return;
	}

	int page_offset, page_seg_offset;
	int page_size = getpagesize();
	char *page_fault_addr = (char *) ALIGN_DOWN((int) info->si_addr,
						   page_size);

	int check = find_page(page_fault_addr);
	/* daca adresa page fault-ulului nu face parte dintr-un segment
	 * al fisierului execurabil, apelez handlerul default
	 */
	if (check == -1) {
		old_action.sa_sigaction(signum, info, context);
		return;
	}
	so_seg_t seg = exec->segments[check];

	page_seg_offset = (int) (page_fault_addr - seg.vaddr);
	page_offset = page_seg_offset + seg.offset;

	/* daca intreaga pagina este inclusa in fisier */
	if (page_seg_offset < seg.file_size)
		mmap((void *) page_seg_offset + seg.vaddr, page_size, seg.perm,
		MAP_FIXED | MAP_PRIVATE, fd, page_offset);
	/* daca pagina se afla in afara fisierului, mapez memprie RAM,
	 * folosind MAP_ANONYMOUS
	 */
	else
		mmap((void *) page_seg_offset + seg.vaddr,
		page_size, seg.perm, MAP_FIXED |
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

int so_init_loader(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	/* initializez handlerul */
	action.sa_sigaction = segv_handler;
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;

	int ret = sigaction(SIGSEGV, &action, &old_action);

	return ret;
}

int so_execute(char *path, char *argv[])
{

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -1;

	exec = so_parse_exec(path);
	if (!exec)
		return -1;
	so_start_exec(exec, argv);

	if (close(fd) == -1)
		return -1;

	return 0;
}
