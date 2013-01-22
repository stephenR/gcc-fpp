#define _GNU_SOURCE

#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <link.h>
#include <string.h>

typedef void (*function_pointer_t)();

static const char jmp_asm[] = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00};

struct jp_element {
	char jmp_asm[sizeof(jmp_asm)];
	void *addr;
	int refcnt;
} __attribute__((packed));

struct jp_empty_slot {
	void *next;
};

union jp_slot {
	struct jp_element filled;
	struct jp_empty_slot empty;
};

struct jp_region {
	union jp_slot *free_list;
	union jp_slot *free_stack;
	struct jp_region *next;
	size_t size;
	union jp_slot slots[];
};

static struct jp_region * const region_list = NULL;

#define INITIAL_NUM_ELEMENTS 256
static const size_t mmap_size = sizeof(struct jp_region) + INITIAL_NUM_ELEMENTS*sizeof(union jp_slot);

static int dl_iterate_phdr_callback (struct dl_phdr_info *info, size_t x, void *data);
static struct jp_region *create_region();
static void lock(struct jp_region *region);
static void unlock(struct jp_region *region);
static int try_resize(struct jp_region *region);

static void fpprotect_init() __attribute__ ((constructor));
static void fpprotect_init()
{
	dl_iterate_phdr (dl_iterate_phdr_callback, NULL);
}

static int
dl_iterate_phdr_callback (struct dl_phdr_info *info, size_t x, void *data)
{
	int j;

	for (j = 0; j < info->dlpi_phnum; j++)
	{
		ElfW(Addr) relocated_start_addr =
			info->dlpi_addr + info->dlpi_phdr[j].p_vaddr;
		ElfW(Addr) unrelocated_start_addr = info->dlpi_phdr[j].p_vaddr;
		ElfW(Addr) start_addr = relocated_start_addr + unrelocated_start_addr;
		ElfW(Word) size_in_memory = info->dlpi_phdr[j].p_memsz;

		if (&region_list < start_addr || (long long) &region_list >= start_addr + size_in_memory)
			continue;

		ElfW(Word) saved_flags = info->dlpi_phdr[j].p_flags;

		ElfW(Addr) mp_low = relocated_start_addr & ~(sysconf(_SC_PAGESIZE) - 1);
		size_t mp_size = relocated_start_addr + size_in_memory - mp_low - 1;

		if (mprotect((void *)mp_low, mp_size, PROT_READ|PROT_WRITE|PROT_EXEC) == -1)
		{
			perror("mprotect");
			_exit(1);
		}

		*((struct jp_region **)&region_list) = create_region();

		if (mprotect((void *)mp_low, mp_size, saved_flags) == -1)
		{
			perror("mprotect");
			_exit(3);
		}

		return 1;
	}
	return 0;
}

static struct jp_region *create_region()
{
	struct jp_region *region = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(region == MAP_FAILED)
	{
		perror("mmap");
		_exit(4);
	}
	/* TODO: is the mmap memory always initialized to 0? */
	region->free_stack = &region->slots;
	region->size = mmap_size;
	lock(region);
	return region;
}

void *__fpp_protect(void *p)
{
	struct jp_element *elem = NULL;
	struct jp_region *region = region_list;
	while (1) {
		if (region->free_stack) {
			unlock(region);
			elem = &region->free_stack->filled;
			++region->free_stack;
			if (region->free_stack >= region + region->size) {
				region->free_stack = NULL;
			}
			break;
		}

		if (region->free_list) {
			unlock(region);
			elem = &region->free_list->filled;
			region->free_list = region_list->free_list->empty.next;
			break;
		} 

		if (region->next) {
			region = region->next;
			continue;
		}

		if(try_resize(region) == 0) {
			continue;
		}

		unlock(region);
		region->next = create_region();
		lock(region);
		region = region->next;
	}
	memcpy(elem->jmp_asm, jmp_asm, sizeof(jmp_asm));
	elem->addr = p;
	elem->refcnt = 1;
	lock(region);
	return elem;
}

function_pointer_t __fpp_verify(void *p)
{
	if(p < region_list || p >= (char *)region_list + region_list->size) {
		puts("failed");
		_exit(1);
	}
	return p;
}

static void lock(struct jp_region *region)
{
	if (mprotect(region, region->size, PROT_READ|PROT_EXEC) == -1)
	{
		perror("mprotect");
		_exit(1);
	}
}

static void unlock(struct jp_region *region)
{
	if (mprotect(region, region->size, PROT_READ|PROT_WRITE) == -1)
	{
		perror("mprotect");
		_exit(1);
	}
}

static int try_resize(struct jp_region *region)
{
	/* TODO: how much to increase? */
	size_t new_size = region->size + mmap_size;

	if (mremap(region, region->size, new_size, 0) == MAP_FAILED)
		return -1;

	unlock(region);
	region->free_stack = (char *) region + region->size;
	region->size = new_size;
	lock(region);
}

int __fpp_compare(const void *p, const void *q)
{
	const struct jp_element *first = p, *second = q;
	if (first->addr == second->addr)
		return 0;
	return 1;
}

