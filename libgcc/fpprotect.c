#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

//#define DEBUG

struct jp_element {
	void *addr;
};

struct jp_region {
	struct jp_element *free_stack;
	struct jp_region *next;
	size_t size;
	struct jp_element slots[];
};

#ifndef SHARED
static struct jp_region * const volatile _fpp_region_list __attribute__((section(".rodata"))) = NULL;
static struct ptr_region *_fpp_ptr_list;
static struct defer_list *_fpp_defer_list;
#endif

#define GLRO(name) _##name
#define GL(name) _##name

#define INITIAL_NUM_ELEMENTS 256
static const size_t mmap_size = sizeof(struct jp_region) + INITIAL_NUM_ELEMENTS*sizeof(struct jp_element);

#define PTR_REGION_ELEMENTS 256
struct ptr_region {
	size_t used_cnt;
	void *slots[PTR_REGION_ELEMENTS];
};

struct defer_list {
	size_t used_cnt;
	struct defer_list *next;
	void **slots[PTR_REGION_ELEMENTS];
};


static struct jp_region *create_region(void);
static void lock(struct jp_region *region);
static void unlock(struct jp_region *region);
static int try_resize(struct jp_region *region);
static struct ptr_region *create_ptr_region(void);
static void protect_deferred_vars(void);

//void __fpp_init(void) __attribute__ ((constructor(101)));
void __fpp_init(void)
{
	int prot = PROT_READ;

#ifndef SHARED
	prot |= PROT_EXEC;
#endif

	if (GLRO(fpp_region_list))
		return;

	long page_size = getpagesize ();

	void *page_addr = (void*) ((long) &GLRO(fpp_region_list) & ~(page_size - 1));

	if (mprotect(page_addr, page_size, PROT_READ|PROT_WRITE|PROT_EXEC) == -1)
	{
//		perror("libfpprotect: mprotect");
		_exit(65);
	}

	*((struct jp_region **)&GLRO(fpp_region_list)) = create_region();

	if (mprotect(page_addr, page_size, prot) == -1)
	{
//		perror("libfpprotect: mprotect");
		_exit(66);
	}

	protect_deferred_vars();
}

static int initialized(void)
{
	return (GLRO(fpp_region_list) != NULL);
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
	struct jp_region *region = GLRO(fpp_region_list);

	while (region) {
		if(pointer_in_region(p, region)) {
			return 1;
		}
		region = region->next;
	}

	return 0;
}

static struct ptr_region *create_ptr_region()
{
	struct ptr_region *region = mmap(NULL, sizeof(struct ptr_region), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(region == MAP_FAILED)
	{
		//perror("libfpprotect: create_ptr_region: mmap");
		_exit(67);
	}
	return region;
}

static struct jp_region *create_region()
{
	struct jp_region *region = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(region == MAP_FAILED)
	{
		//perror("libfpprotect: mmap");
		_exit(68);
	}
	region->free_stack = region->slots;
	region->size = mmap_size;
	lock(region);
	return region;
}

void *__fpp_protect(void *p)
{
	struct jp_element *elem = NULL;
	struct jp_region *region;

	/* ignore NULL pointer */
	if (!p)
		return p;

	if (!initialized()) {
		__fpp_init();
		////fputs("libfpprotect: __fpp_protect not initialized, aborting!", stderr);
		//_exit(1);
	}

	region = GLRO(fpp_region_list);

	/* TODO: only for debugging purposes */
	if(pointer_in_region_list(p)) {
		//fputs("libfpprotect: __fpp_protect called twice!", stderr);
		_exit(69);
	}

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
	//memcpy(elem->jmp_asm_pre, jmp_asm_pre, sizeof(jmp_asm_pre));
	//memcpy(elem->jmp_asm_post, jmp_asm_post, sizeof(jmp_asm_post));
	elem->addr = p;
	lock(region);
	return elem;
}

static void **get_global_var_ptr(void)
{
	void ** ret;

	if (!GL(fpp_ptr_list) || GL(fpp_ptr_list)->used_cnt >= PTR_REGION_ELEMENTS)
		GL(fpp_ptr_list) = create_ptr_region();

	ret = &GL(fpp_ptr_list)->slots[GL(fpp_ptr_list)->used_cnt];

	++GL(fpp_ptr_list)->used_cnt;

	return ret;
}

static void create_defer_list(void)
{
	struct defer_list *current = GL(fpp_defer_list);

	struct defer_list *new = mmap(NULL, sizeof(struct ptr_region), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(new == MAP_FAILED)
		_exit(73);

	new->next = current;

	GL(fpp_defer_list) = new;
}

static void defer_protection(void **var_ptr)
{
	if (initialized()) {
		*var_ptr = __fpp_protect(*var_ptr);
		return;
	}

	if (!GL(fpp_defer_list) || GL(fpp_defer_list)->used_cnt >= PTR_REGION_ELEMENTS)
		create_defer_list();

	GL(fpp_defer_list)->slots[GL(fpp_defer_list)->used_cnt] = var_ptr;

	++GL(fpp_defer_list)->used_cnt;
}

static void protect_deferred_vars(void)
{
	struct defer_list *defer_list;
	size_t i;
	
	for (defer_list = GL(fpp_defer_list); defer_list; defer_list = defer_list->next) {
		for (i = 0; i < defer_list->used_cnt; ++i) {
			void **var = defer_list->slots[i];
			*var = __fpp_protect(*var);
		}
	}
}

/* TODO: improve memory management */
void *fpp_protect_func_ptr (void *p)
{
	void ** global_var;

	if (!p)
		return p;

	global_var = get_global_var_ptr();
	*global_var = p;

	defer_protection(global_var);

	return (void *) global_var;
}

void *__fpp_verify(void *p);

void *__fpp_verify(void *p)
{
	const struct jp_element **elem = p;

	if (!initialized())
		return *(void **)p;

	if(!pointer_in_region_list(*elem)) {
		//fprintf(stderr, "libfpprotect: __fpp_verify failed with p=%p, aborting!", p);
		_exit(70);
	}

	return (*elem)->addr;
}

void *__fpp_deref(void *p)
{
	struct jp_element *elem;

	if (!p)
		return p;

	if (!initialized())
		return *(void **) p;

	elem = * (struct jp_element **) p;

	/* This can happen with undefined weak symbols */
	if (!elem)
		return elem;

	return elem->addr;
}

static void lock(struct jp_region *region)
{
	if (mprotect(region, region->size, PROT_READ|PROT_EXEC) == -1)
	{
		//perror("libfpprotect: mprotect");
		_exit(71);
	}
}

static void unlock(struct jp_region *region)
{
	if (mprotect(region, region->size, PROT_READ|PROT_WRITE) == -1)
	{
		//perror("libfpprotect: mprotect");
		_exit(72);
	}
}

static int try_resize(struct jp_region *region)
{
	/* TODO: how much to increase? */
	size_t new_size = region->size + INITIAL_NUM_ELEMENTS*sizeof(struct jp_element);

	if (mremap(region, region->size, new_size, 0) == MAP_FAILED)
		return -1;

	unlock(region);
	region->free_stack = region_end(region);
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


