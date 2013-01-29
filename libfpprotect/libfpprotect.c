#define _GNU_SOURCE

#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <link.h>
#include <string.h>

#define DEBUG

#ifdef __x86_64__
static const char jmp_asm_pre[] = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00}; //jmp *(%rip)
static const char jmp_asm_post[] = {};
#endif
#ifdef __i386__
static const char jmp_asm_pre[] = {0x68};  //push $addr
static const char jmp_asm_post[] = {0xc3}; //ret
#endif

struct jp_element {
	char jmp_asm_pre[sizeof(jmp_asm_pre)];
	void *addr;
	char jmp_asm_post[sizeof(jmp_asm_post)];
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
static struct jp_region * const * const volatile region_list_ptr = &region_list;

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
	if(!dl_iterate_phdr (dl_iterate_phdr_callback, NULL)) {
		fprintf(stderr, "libfpprotect: fpprotect_init failed, aborting!");
		_exit(1);
	}
}

static int dl_iterate_phdr_callback (struct dl_phdr_info *info, __attribute__((unused)) size_t size, __attribute__((unused)) void *data)
{
	int j;

	for (j = 0; j < info->dlpi_phnum; j++)
	{
		ElfW(Addr) relocated_start_addr =
			info->dlpi_addr + info->dlpi_phdr[j].p_vaddr;
		ElfW(Addr) unrelocated_start_addr = info->dlpi_phdr[j].p_vaddr;
		ElfW(Addr) start_addr = relocated_start_addr + unrelocated_start_addr;
		ElfW(Word) size_in_memory = info->dlpi_phdr[j].p_memsz;

		if ((ElfW(Addr)) &region_list < start_addr
				|| (ElfW(Addr)) &region_list >= start_addr + size_in_memory)
			continue;

		ElfW(Word) saved_flags = info->dlpi_phdr[j].p_flags;

		ElfW(Addr) mp_low = relocated_start_addr & ~(sysconf(_SC_PAGESIZE) - 1);
		size_t mp_size = relocated_start_addr + size_in_memory - mp_low - 1;

		if (mprotect((void *)mp_low, mp_size, PROT_READ|PROT_WRITE|PROT_EXEC) == -1)
		{
			perror("libfpprotect: mprotect");
			_exit(1);
		}

		*((struct jp_region **)&region_list) = create_region();

		if (mprotect((void *)mp_low, mp_size, saved_flags) == -1)
		{
			perror("libfpprotect: mprotect");
			_exit(3);
		}

		return 1;
	}
	return 0;
}

static void *region_end(struct jp_region *region)
{
	return (char *) region + region->size;
}

static int pointer_in_region(const void *p, struct jp_region *region)
{
	return (p >= (void *) region->slots && p < region_end(region));
}

static int pointer_in_region_list(const void *p)
{
	struct jp_region *region = *region_list_ptr;

	while (region) {
		if(pointer_in_region(p, region)) {
			return 1;
		}
		region = region->next;
	}

	return 0;
}

static struct jp_region *create_region()
{
	struct jp_region *region = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(region == MAP_FAILED)
	{
		perror("libfpprotect: mmap");
		_exit(4);
	}
	/* TODO: is the mmap memory always initialized to 0? */
	region->free_stack = region->slots;
	region->size = mmap_size;
	lock(region);
	return region;
}

void *__fpp_protect(void *p)
{
	struct jp_element *elem = NULL;
	struct jp_region *region = *region_list_ptr;

	/* ignore NULL pointer */
	if (!p)
		return p;

	while (1) {
		if (region->free_stack) {
			unlock(region);
			elem = &region->free_stack->filled;
			++region->free_stack;
			if ((void *) region->free_stack >= region_end(region)) {
				region->free_stack = NULL;
			}
			break;
		}

		if (region->free_list) {
			unlock(region);
			elem = &region->free_list->filled;
			region->free_list = (*region_list_ptr)->free_list->empty.next;
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
	memcpy(elem->jmp_asm_pre, jmp_asm_pre, sizeof(jmp_asm_pre));
	memcpy(elem->jmp_asm_post, jmp_asm_post, sizeof(jmp_asm_post));
	elem->addr = p;
	elem->refcnt = 1;
	lock(region);
	return elem;
}

void __fpp_verify(void *p)
{
	if(!pointer_in_region_list(p)) {
		fprintf(stderr, "libfpprotect: __fpp_verify failed with p=%p, aborting!", p);
		_exit(1);
	}
}

static void lock(struct jp_region *region)
{
	if (mprotect(region, region->size, PROT_READ|PROT_EXEC) == -1)
	{
		perror("libfpprotect: mprotect");
		_exit(1);
	}
}

static void unlock(struct jp_region *region)
{
	if (mprotect(region, region->size, PROT_READ|PROT_WRITE) == -1)
	{
		perror("libfpprotect: mprotect");
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
	region->free_stack = (union jp_slot *) ((char *) region + region->size);
	region->size = new_size;
	lock(region);

	return 0;
}

int __fpp_eq(const void *p, const void *q)
{
	if (pointer_in_region_list(p)) {
		p = ((const struct jp_element *) p)->addr;
	}
	if (pointer_in_region_list(q)) {
		q = ((const struct jp_element *) q)->addr;
	}

	return (p == q);
}

static struct jp_region *get_region_for(union jp_slot *slot) {
	struct jp_region *region = *region_list_ptr;
	while (region) {
		if (pointer_in_region(slot, region))
			return region;
		region = region->next;
	}
	return NULL;
}

void __fpp_del(void *p)
{
	struct jp_region *region;
	union jp_slot *slot = (union jp_slot *) p;

	if (!slot)
		return;

	if (!slot->filled.refcnt)
		return;

	region = get_region_for(slot);

#ifdef DEBUG
	if (!region) {
		fprintf(stderr, "libfpprotect: __fpp_del failed with slot=%p, aborting!", slot);
		_exit(2);
	}
#endif

	unlock(region);
	--slot->filled.refcnt;
	if (!slot->filled.refcnt) {
		slot->filled.addr = NULL;
		slot->empty.next = region->free_list;
		region->free_list = slot;
	}
	lock(region);

}

void *__fpp_cpy(void *p)
{
	struct jp_region *region;
	union jp_slot *slot = (union jp_slot *) p;

	if (!slot)
		return NULL;

	if (!slot->filled.refcnt)
		return slot;

	region = get_region_for(slot);

#ifdef DEBUG
	if (!region) {
		fprintf(stderr, "libfpprotect: __fpp_cpy failed with slot=%p, aborting!", slot);
		_exit(2);
	}
#endif

	unlock(region);
        ++slot->filled.refcnt;
	lock(region);

	return slot;
}

void __fpp_make_immutable(void *p)
{
	struct jp_region *region;
	union jp_slot *slot = (union jp_slot *) p;

	if (!slot)
		return;

	if (!slot->filled.refcnt)
		return;

	region = get_region_for(slot);

#ifdef DEBUG
	if (!region) {
		fprintf(stderr, "libfpprotect: __fpp_make_immutable failed with slot=%p, aborting!", slot);
		_exit(2);
	}
#endif

	unlock(region);
        slot->filled.refcnt = 0;
	lock(region);

	return;
}

