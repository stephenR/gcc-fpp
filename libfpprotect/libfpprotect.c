#define _GNU_SOURCE

#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <link.h>

static const long long __fpp_reg = 0;

static const size_t mmap_initial_size = 4096;

static int dl_iterate_phdr_callback (struct dl_phdr_info *info, size_t x, void *data);

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

      if ((long long) &__fpp_reg < start_addr || (long long) &__fpp_reg >= start_addr + size_in_memory)
	      continue;

      ElfW(Word) saved_flags = info->dlpi_phdr[j].p_flags;

      ElfW(Addr) mp_low = relocated_start_addr & ~(sysconf(_SC_PAGESIZE) - 1);
      size_t mp_size = relocated_start_addr + size_in_memory - mp_low - 1;

      if (mprotect((void *)mp_low, mp_size, PROT_READ|PROT_WRITE|PROT_EXEC) == -1)
        {
          perror("mprotect");
          return -1;
        }

      *((void **)&__fpp_reg) = mmap(NULL, mmap_initial_size, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if((void *)__fpp_reg == MAP_FAILED)
        {
        perror("mprotect");
        return -2;
	}

      if (mprotect((void *)mp_low, mp_size, saved_flags) == -1)
        {
          perror("mprotect");
	  return -3;
        }

      return 1;
    }
  return 0;
}

void __fpp_foo(void * x)
{
	printf("x=%p, __fpp_reg=%p\n", x, __fpp_reg);
}

