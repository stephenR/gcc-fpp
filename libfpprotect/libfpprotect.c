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
} __attribute__((packed));

struct jp_region {
	struct jp_element *free_stack;
	struct jp_region *next;
	size_t size;
	struct jp_element slots[];
};

static struct jp_region * const volatile region_list __attribute__((section(".rodata"))) = NULL;

#define INITIAL_NUM_ELEMENTS 256
static const size_t mmap_size = sizeof(struct jp_region) + INITIAL_NUM_ELEMENTS*sizeof(struct jp_element);

static struct jp_region *create_region();
static void lock(struct jp_region *region);
static void unlock(struct jp_region *region);
static int try_resize(struct jp_region *region);

void __fpp_init() __attribute__ ((constructor(101)));
void __fpp_init()
{
	if (region_list)
		return;

	long page_size = sysconf(_SC_PAGESIZE);

	void *page_addr = (void*) ((long) &region_list & ~(page_size - 1));

	if (mprotect(page_addr, page_size, PROT_READ|PROT_WRITE|PROT_EXEC) == -1)
	{
		perror("libfpprotect: mprotect");
		_exit(1);
	}

	*((struct jp_region **)&region_list) = create_region();

	if (mprotect(page_addr, page_size, PROT_READ|PROT_EXEC) == -1)
	{
		perror("libfpprotect: mprotect");
		_exit(3);
	}

}

static int initialized()
{
	return (region_list != NULL);
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
	struct jp_region *region = region_list;

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
	struct jp_region *region = region_list;

	if (!initialized())
		return p;

	/* ignore NULL pointer */
	if (!p)
		return p;

	while (1) {
		if (region->free_stack) {
			unlock(region);
			elem = region->free_stack;
			++region->free_stack;
			if ((void *) region->free_stack >= region_end(region)) {
				region->free_stack = NULL;
			}
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
	lock(region);
	return elem;
}

void __fpp_verify(void *p)
{
	if (!initialized())
		return;

	if(!pointer_in_region_list(p)) {
		fprintf(stderr, "libfpprotect: __fpp_verify failed with p=%p, aborting!", p);
		_exit(1);
	}

	return;
}

void *__fpp_get_addr(void *p)
{
	const struct jp_element *elem = p;

	if (!pointer_in_region_list(p))
		return p;

	return elem->addr;
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
	region->free_stack = (struct jp_element *) ((char *) region + region->size);
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


