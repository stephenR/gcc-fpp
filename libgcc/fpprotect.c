#ifndef inhibit_libc

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

//#define DEBUG

#define TRUE 1
#define FALSE 0

union ptr_region_slot {
	union ptr_region_slot *next;
	void *addr;
};

struct ptr_region {
	size_t slot_cnt;
	size_t used_cnt;
	union ptr_region_slot *free_list;
	struct ptr_region *next;
	union ptr_region_slot slots[];
};

extern struct ptr_region **__dl_fpp_region_list(void);
extern struct ptr_region **__dl_fpp_defer_list(void);
extern void __dl_fpp_mutex_lock(void);
extern void __dl_fpp_mutex_unlock(void);

static struct ptr_region *_fpp_ptr_list;
static struct ptr_region *_fpp_perm_ptr_list;

#define GL(name) _##name

#define INITIAL_NUM_ELEMENTS 256
static const size_t mmap_size = sizeof(struct ptr_region) + INITIAL_NUM_ELEMENTS*sizeof(union ptr_region_slot);

static struct ptr_region *create_region(int read_only);
static void lock(struct ptr_region *region);
static void unlock(struct ptr_region *region);
static int try_resize(struct ptr_region *region, int read_only);
static void protect_deferred_vars(void);
static void **alloc_ptr(struct ptr_region *region, void *val, int read_only);
static void free_ptr(struct ptr_region *region_list, void *p, int read_only);
static struct ptr_region *expand_ptr_region(struct ptr_region *region, int read_only);
static int initialized(void);
static void *__fpp_protect_internal(void *p);
static void **find_protected_ptr(void *p);

static struct ptr_region **region_list_addr(void) {
	return __dl_fpp_region_list();
}

static struct ptr_region **defer_list_addr(void) {
	return __dl_fpp_defer_list();
}

static void fpp_mutex_lock(void) {
	if (initialized())
		__dl_fpp_mutex_lock();
}

static void fpp_mutex_unlock(void) {
	if (initialized())
		__dl_fpp_mutex_unlock();
}

static void __fpp_init(void)
{
	int prot = PROT_READ;

#ifndef SHARED
	prot |= PROT_EXEC;
#endif

	if (*region_list_addr())
		return;

	long page_size = getpagesize ();

	void *page_addr = (void*) ((long) region_list_addr() & ~(page_size - 1));

	if (mprotect(page_addr, page_size, PROT_READ|PROT_WRITE|PROT_EXEC) == -1)
	{
//		perror("libfpprotect: mprotect");
		_exit(65);
	}

	*region_list_addr() = create_region(TRUE);

	if (mprotect(page_addr, page_size, prot) == -1)
	{
//		perror("libfpprotect: mprotect");
		_exit(66);
	}

	protect_deferred_vars();
}

static int initialized(void)
{
	return (*region_list_addr() != NULL);
}

static size_t region_size(struct ptr_region* region)
{
	return sizeof(struct ptr_region) + region->slot_cnt * sizeof(union ptr_region_slot);
}

static void *region_end(struct ptr_region *region)
{
	return (char *) region + region_size(region);
}

static int pointer_in_region(const void *p, struct ptr_region *region)
{
	return (p >= (void *) region->slots && p < region_end(region));
}

static struct ptr_region *region_for_ptr(struct ptr_region *region, const void *p)
{
	while (region) {
		if(pointer_in_region(p, region)) {
			return region;
		}
		region = region->next;
	}

	return NULL;
}

static struct ptr_region *create_region(int read_only)
{
	struct ptr_region *region = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(region == MAP_FAILED)
	{
		//perror("libfpprotect: mmap");
		_exit(68);
	}

	region->slot_cnt = INITIAL_NUM_ELEMENTS;

	if (read_only)
		lock(region);

	return region;
}

void *__fpp_protect(void *p)
{
	void *ret;

	fpp_mutex_lock();
	ret = __fpp_protect_internal(p);
	fpp_mutex_unlock();

	return ret;
}

static void *__fpp_protect_internal(void *p)
{
	struct ptr_region *region;

	/* ignore NULL pointer */
	if (!p)
		return p;

	if (!initialized()) {
		__fpp_init();
	}

	region = *region_list_addr();

	/* TODO: only for debugging purposes */
	if(region_for_ptr(*region_list_addr(), p)) {
		//fputs("libfpprotect: __fpp_protect called twice!", stderr);
		_exit(69);
	}

	return alloc_ptr(region, p, TRUE);
}

static void defer_protection(void **var_ptr)
{
	if (initialized()) {
		*var_ptr = __fpp_protect_internal(*var_ptr);
		return;
	}

	alloc_ptr(*defer_list_addr(), var_ptr, FALSE);
}

static void protect_deferred_vars(void)
{
	struct ptr_region *defer_list;
	size_t i;
	
	for (defer_list = *defer_list_addr(); defer_list; defer_list = defer_list->next) {
		for (i = 0; i < defer_list->used_cnt; ++i) {
			void **var = defer_list->slots[i].addr;
			*var = __fpp_protect_internal(*var);
		}
	}
	/* TODO delete processed defer_list */
}

void *fpp_protect_func_ptr (void *p)
{
	void ** global_var;

	if (!p)
		return p;

	fpp_mutex_lock();

	if (!_fpp_ptr_list)
		_fpp_ptr_list = create_region (FALSE);

	global_var = alloc_ptr(_fpp_ptr_list, p, FALSE);

	defer_protection(global_var);

	fpp_mutex_unlock();
	return global_var;
}

void *fpp_protect_func_ptr_perm (void *p)
{
	void ** global_var;

	if (!p)
		return p;

	fpp_mutex_lock();

	if (!_fpp_ptr_list)
		_fpp_ptr_list = create_region (FALSE);

	global_var = find_protected_ptr(p);

	if (!global_var) {
		global_var = alloc_ptr(_fpp_perm_ptr_list, p, FALSE);
		defer_protection(global_var);
	}

	fpp_mutex_unlock();
	return global_var;
}

void *__fpp_verify(void *p)
{
	const union ptr_region_slot *slot;

	if (!initialized())
		return *(void **)p;

	fpp_mutex_lock();

	slot = *(union ptr_region_slot **) p;

	if(!region_for_ptr(*region_list_addr(), slot)) {
		//fprintf(stderr, "libfpprotect: __fpp_verify failed with p=%p, aborting!", p);
		_exit(70);
	}

	fpp_mutex_unlock();

	return slot->addr;
}

void *__fpp_deref(void *p)
{
	union ptr_region_slot *slot;
	void *ret;

	if (!p)
		return p;

	if (!initialized())
		return *(void **) p;

	fpp_mutex_lock();

	slot = *(union ptr_region_slot **) p;

	/* This can happen with undefined weak symbols */
	if (!slot)
		ret = slot;
	else
		ret = slot->addr;

	fpp_mutex_unlock();

	return ret;
}

static void lock(struct ptr_region *region)
{
	if (mprotect(region, region_size(region), PROT_READ|PROT_EXEC) == -1)
	{
		//perror("libfpprotect: mprotect");
		_exit(71);
	}
}

static void unlock(struct ptr_region *region)
{
	if (mprotect(region, region_size(region), PROT_READ|PROT_WRITE) == -1)
	{
		//perror("libfpprotect: mprotect");
		_exit(72);
	}
}

static int try_resize(struct ptr_region *region, int read_only)
{
	size_t new_size = region_size(region) + INITIAL_NUM_ELEMENTS*sizeof(union ptr_region_slot);

	if (mremap(region, region_size(region), new_size, 0) == MAP_FAILED)
		return -1;

	if (read_only)
		unlock(region);
	region->slot_cnt += INITIAL_NUM_ELEMENTS;
	if (read_only)
		lock(region);

	return 0;
}

void fpp_free_func_ptr (void *p)
{
	if (!p)
		return;

	fpp_mutex_lock();

	/* TODO: is this code correct? */

	if (initialized()){
		/* remove the protected ptr */
		free_ptr (*region_list_addr(), p, TRUE);
	} else {
		/* remove the pointer from the defer list */
		free_ptr (*defer_list_addr(), p, FALSE);
	}

	/* finally, remove the global var */
	free_ptr (_fpp_ptr_list, p, FALSE);

	fpp_mutex_unlock();
}

static void **alloc_ptr(struct ptr_region *region, void *val, int read_only)
{
	void **ret = NULL;

	/* Find empty slots in the region list */
	while (TRUE) {
		if (region->free_list) {
			ret = &region->free_list->addr;
			if (read_only)
				unlock(region);
			region->free_list = region->free_list->next;
			*ret = val;
			if (read_only)
				lock(region);
			return ret;
		}

		if (region->used_cnt < region->slot_cnt) {
			ret = &region->slots[region->used_cnt].addr;
			if (read_only)
				unlock(region);
			++region->used_cnt;
			*ret = val;
			if (read_only)
				lock(region);
			return ret;
		}

		if (!region->next)
			break;

		region = region->next;
	}

	/* No free slot found, region points to the last element in the list */
	region = expand_ptr_region(region, read_only);
	ret = &region->slots[region->used_cnt].addr;
	if (read_only)
		unlock(region);
	++region->used_cnt;
	*ret = val;
	if (read_only)
		lock(region);
	return ret;
}

static void free_ptr(struct ptr_region *region_list, void *p, int read_only)
{
	struct ptr_region *region = region_for_ptr(region_list, p);
	union ptr_region_slot *slot = p;

	if (!region)
		_exit(73);

	if (read_only)
		unlock(region);
	slot->next = region->free_list;
	region->free_list = slot;
	if (read_only)
		lock(region);
}

static struct ptr_region *expand_ptr_region(struct ptr_region *region, int read_only)
{
	if (try_resize(region, read_only) == 0)
		return region;

	if (read_only)
		unlock(region);
	region->next = create_region(read_only);
	if (read_only)
		lock(region);

	return region->next;
}

static int global_var_is_fp(void *global, void *fp)
{
	if (!initialized())
		return (global == fp);

	return (*((void **) global) == fp);
}

static void **find_protected_ptr(void *p)
{
	size_t i;
	const struct ptr_region *region = _fpp_perm_ptr_list;

	while (region) {
		for (i = 0; i < region->used_cnt; ++i) {
			if (global_var_is_fp(region->slots[i].addr, p))
				return &region->slots[i].addr;
		}
		region = region->next;
	}

	return NULL;
}

#else  /* inhibit_libc */
void fpp_free_func_ptr (void *p){
}
void *__fpp_deref(void *p){
	if (!p)
		return p;
	return *(void **) p;
}
void *__fpp_verify(void *p){
	if (!p)
		return p;
	return *(void **)p;
}
#define ARRAY_SIZE 256
static int dynamic_cnt = 0;
static void *global_vars[ARRAY_SIZE];
void *fpp_protect_func_ptr (void *p){
	if (!p)
		return p;
	if (dynamic_cnt >= ARRAY_SIZE)
		return (void *) 0;
	global_vars[dynamic_cnt] = p;
	return &global_vars[dynamic_cnt++];
}
void *fpp_protect_func_ptr_perm (void *p){
	return fpp_protect_func_ptr(p);
}
void *__fpp_protect(void *p){
	return p;
}
#endif /* inhibit_libc */
