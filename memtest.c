// SPDX-License-Identifier: GPL-2.0

/*
 * Author: Wladislav Wiebe <wladislav.wiebe@nokia.com>
 *
 * Copyright (c) 2020 Nokia
 *
 * This module allocates all available system memory besides configurable
 * @free_*_space to avoid oom situations. In case test finds
 * broken memory segments, physical and virtual affected memory will be printed.
 *
 * In case of CONFIG_HIGHMEM, memory test will go through
 * HighMem, LowMem (Slab) and Vmalloc memory.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define PAGES_TO_BYTE(n_pages) ((u64)(n_pages) << PAGE_SHIFT)
#define PAGES_TO_KB(n_pages) ((u64)(n_pages) << (PAGE_SHIFT - 10))
#define PAGES_TO_MB(n_pages) (PAGES_TO_KB((u64)n_pages) >> 10)
#define BYTE_TO_MB(num) ((u64)num >> 10 >> 10)
#define MB_TO_BYTE(num) ((u64)num << 10 << 10)

static struct memtest {
	char *test_area;
	u64 test_area_size;
} mt;

static unsigned int free_sysmem_space = 100;
module_param(free_sysmem_space, uint, 0644);
MODULE_PARM_DESC(free_sysmem_space,
		 "Reserve free space (in MB) for system memory, default is 100");

static unsigned int free_slab_space = 10;
module_param(free_slab_space, uint, 0644);
MODULE_PARM_DESC(free_slab_space,
		 "Reserve free space (in MB) for Slab memory on HighMem arch, default is 10");

static unsigned int free_vmalloc_space = 10;
module_param(free_vmalloc_space, uint, 0644);
MODULE_PARM_DESC(free_vmalloc_space,
		 "Reserve free space (in MB) for Vmalloc memory on HighMem arch, default is 10");

static bool test_highmem = 1;
module_param(test_highmem, bool, 0644);
MODULE_PARM_DESC(test_highmem, "Test HighMem memory, default is 1");

static bool test_slab = 1;
module_param(test_slab, bool, 0644);
MODULE_PARM_DESC(test_slab, "Test Slab memory on HighMem arch, default is 1");

static bool test_vmalloc = 1;
module_param(test_vmalloc, bool, 0644);
MODULE_PARM_DESC(test_vmalloc, "Test Vmalloc memory on HighMem arch, default is 1");

static u8 test_pattern = 0x5;
module_param(test_pattern, byte, 0644);
MODULE_PARM_DESC(test_pattern,
		 "Test pattern written to tested memory, default is 0x5");

static unsigned int max_runs = 3;
module_param(max_runs, uint, 0644);
MODULE_PARM_DESC(max_runs,
		 "How many times should allocated memory being checked, default is 3");

static unsigned int pause_time = 3;
module_param(pause_time, uint, 0644);
MODULE_PARM_DESC(pause_time,
		 "Pause time in seconds between test runs, default is 3");

static bool stop_test;
module_param(stop_test, bool, 0644);
MODULE_PARM_DESC(stop_test, "Interrupt test by passing 1");


static void meminfo_show(const char *info)
{
	struct sysinfo si;
	char mem_info[200];

	strncpy(mem_info, info, ARRAY_SIZE(mem_info) - 1);
	si_meminfo(&si);
	pr_emerg("************ %s ************\n", mem_info);
	pr_emerg("MemTotal: %llu MB, MemFree: %llu MB, MemAvailable: %llu MB\n",
		 PAGES_TO_MB(si.totalram),
		 PAGES_TO_MB(si.freeram),
		 PAGES_TO_MB(si_mem_available()));

	if (IS_ENABLED(CONFIG_HIGHMEM)) {
		pr_emerg("HighTotal: %llu MB, HighFree: %llu MB, LowTotal: %llu MB, LowFree: %llu MB, VmallocTotal: %llu MB\n",
			 PAGES_TO_MB(si.totalhigh),
			 PAGES_TO_MB(si.freehigh),
			 PAGES_TO_MB(si.totalram - si.totalhigh),
			 PAGES_TO_MB(si.freeram - si.freehigh),
			 BYTE_TO_MB(VMALLOC_TOTAL));
	}
	pr_emerg("*******************************************************\n");
}

static unsigned long get_page_addr_offset(char *addr)
{
	unsigned long offset = 0;

	offset = (unsigned long)(addr) -
		 PAGE_ALIGN((unsigned long)(addr) -
		 PAGE_SIZE);
	if (offset == PAGE_SIZE)
		offset = 0;

	return offset;
}

static u64 get_phys_addr(char *addr)
{
	u64 phys_addr = 0;
	struct page *pg;

	pg = kmap_to_page(addr);

	if (is_vmalloc_addr(addr)) {
		phys_addr = PFN_PHYS(vmalloc_to_pfn(addr)) +
			    get_page_addr_offset(addr);
	} else if (PageHighMem(pg))
		phys_addr = page_to_phys(pg) + get_page_addr_offset(addr);
	else
		phys_addr = virt_to_phys(addr);

	return phys_addr;
}

static void dump_mem_addr(struct memtest *mt, char *info)
{
	char addr_info[200];

	strncpy(addr_info, info, ARRAY_SIZE(addr_info) - 1);

	pr_emerg("%s: PHYS addr: 0x%llx, VIRT addr: 0x%p\n",
		 addr_info, get_phys_addr(mt->test_area), mt->test_area);
}

static int scan_mem(struct memtest *mt)
{
	int ret = 0;
	u64 i = 0;

	while (i < mt->test_area_size && !stop_test) {
		if (*(mt->test_area + i) != test_pattern) {
			pr_emerg("ERROR: byte changed from 0x%x to 0x%x at PHYS addr: 0x%llx, VIRT addr: 0x%p\n",
				 test_pattern,
				 *(mt->test_area + i),
				 get_phys_addr(mt->test_area + i),
				 (mt->test_area + i));

			ret = -EILSEQ;
		}
		i++;
	}

	return ret;
}

static void sleep_and_check_testrun_state(int *fail)
{
	msleep(pause_time * 1000);
	if (*fail == 0)
		pr_emerg("run PASSED\n");
	else
		pr_emerg("run FAILED\n");
}

static int test_highmem_arch(void)
{
	struct page **pg;
	struct sysinfo si;
	int ret = 0, fail = 0;
	u64 page_count = 0, i = 0, j = 0;
	u64 alloc_total_mem = 0;

	pr_emerg("++++++++++ Testing HighMem ++++++++++\n");
	si_meminfo(&si);

	if (MB_TO_BYTE(free_sysmem_space) > PAGES_TO_BYTE(si.freehigh)) {
		pr_emerg("Not enough memory to test!\n");
		return -ENOMEM;
	}

	alloc_total_mem = PAGES_TO_BYTE(si.freehigh) -
			  MB_TO_BYTE(free_sysmem_space);
	page_count = alloc_total_mem / PAGE_SIZE;
	mt.test_area_size = PAGE_SIZE;

	pr_emerg("Try to allocate %llu MB HighMem, %llu pages\n",
		 BYTE_TO_MB(alloc_total_mem), page_count);

	pg = vmalloc(page_count * sizeof(char *));
	if (!pg) {
		pr_emerg("unable to vmalloc page list\n");
		return -ENOMEM;
	}

	for (i = 0; i < page_count; i++) {
		pg[i] = alloc_page(__GFP_HIGHMEM);
		if (!pg[i]) {
			pr_emerg("unable to alloc page\n");
			for (i = i - 1; i == 0; i--)
				__free_page(pg[i]);
			vfree(pg);
			return -ENOMEM;
		}
	}

	meminfo_show("Meminfo during HighMem test");

	for (j = 0; j < max_runs && !stop_test; j++) {
		pr_emerg("starting test %llu of %d\n", j + 1, max_runs);
		for (i = 0; i < page_count && !stop_test; i++) {
			mt.test_area = kmap(pg[i]);
			if (!mt.test_area) {
				pr_emerg("unable to kmap memory test area\n");
				ret = -ENOMEM;
				break;
			}
			if (j == 0)
				memset(mt.test_area, test_pattern,
				       mt.test_area_size);
			if (i == 0 && j == 0)
				dump_mem_addr(&mt, "HighMem start");
			ret = scan_mem(&mt);
			kunmap(pg[i]);
			if (ret < 0)
				fail = ret;
			ret = 0;
		}
		if (ret < 0)
			break;

		sleep_and_check_testrun_state(&fail);
	}

	for (i = 0; i < page_count; i++)
		__free_page(pg[i]);

	vfree(pg);
	ret = fail;

	return ret;
}

static int test_slab_on_highmem_arch(void)
{
	struct sysinfo si;
	char **page_list;
	int ret = 0, fail = 0;
	u64 page_count = 0, i = 0, j = 0;
	u64 alloc_total_mem = 0;

	pr_emerg("++++++++++ Testing Slab memory ++++++++++\n");
	mt.test_area_size = PAGE_SIZE;

	si_meminfo(&si);

	if (MB_TO_BYTE(free_slab_space) >
	   (PAGES_TO_BYTE(si.freeram - si.freehigh))) {
		pr_emerg("Not enough memory to test!\n");
		return -ENOMEM;
	}

	alloc_total_mem = PAGES_TO_BYTE(si.freeram - si.freehigh) -
			  MB_TO_BYTE(free_slab_space);
	page_count = alloc_total_mem / PAGE_SIZE;
	mt.test_area_size = PAGE_SIZE;

	pr_emerg("Try to allocate %llu MB Slab memory, %llu pages\n",
		 BYTE_TO_MB(alloc_total_mem), page_count);

	page_list = vmalloc(page_count * sizeof(char *));
	if (!page_list) {
		pr_emerg("unable to vmalloc Slab memory page_list\n");
		return -ENOMEM;
	}

	for (i = 0; i < page_count; i++) {
		page_list[i] = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (!page_list[i]) {
			pr_emerg("unable to allocate Slab memory\n");
			for (i = i - 1; i == 0; i--)
				kfree(page_list[i]);
			vfree(page_list);
			return -ENOMEM;
		}
	}

	meminfo_show("Meminfo during Slab memory test");

	for (j = 0; j < max_runs && !stop_test; j++) {
		pr_emerg("starting test %llu of %d\n", j + 1, max_runs);
		for (i = 0; i < page_count && !stop_test; i++) {
			mt.test_area = page_list[i];
			if (j == 0)
				memset(mt.test_area, test_pattern,
				       mt.test_area_size);
			if (i == 0 && j == 0)
				dump_mem_addr(&mt, "Slab start");
			ret = scan_mem(&mt);
			if (ret < 0)
				fail = ret;
		}
		sleep_and_check_testrun_state(&fail);
	}

	for (i = 0; i < page_count; i++)
		kfree(page_list[i]);

	vfree(page_list);
	ret = fail;

	return ret;
}

static int test_vmalloc_on_highmem_arch(void)
{
	char **vm_list;
	int ret = 0, fail = 0;
	u64 vm_count = 0, i = 0, j = 0;

	/*
	 * We cannot get on all kernel versions VmallocUsed.
	 * E.g. up to 4.4 kernel is VmallocUsed 0 due to commit:
	 * a5ad88ce8c7 "mm: get rid of 'vmalloc_info' from /proc/meminfo"
	 * Allocation strategy is in this case different than in other
	 * memory tests. We allocate all available Vmalloc memory with 1 MB
	 * chunks until we get NOMEM, than freeing the  @free_vmalloc_space
	 * from totally allocated vmalloc memory.
	 */

	pr_emerg("++++++++++ Testing Vmalloc memory ++++++++++\n");
	mt.test_area_size = MB_TO_BYTE(1);

	vm_list = kmalloc_array(BYTE_TO_MB(VMALLOC_TOTAL), sizeof(char *),
				GFP_KERNEL);
	if (!vm_list)
		return -ENOMEM;

	while (true) {
		vm_list[vm_count] = __vmalloc(mt.test_area_size,
					      GFP_KERNEL | __GFP_NOWARN,
					      PAGE_KERNEL);
		if (!vm_list[vm_count])
			break;

		vm_count++;
	}
	if (vm_count > free_vmalloc_space) {
		vm_count = vm_count - free_vmalloc_space;
		for (i = vm_count; i < vm_count + free_vmalloc_space; i++)
			vfree(vm_list[i]);
	} else {
		pr_emerg("Not enough memory to test!\n");
		fail = -ENOMEM;
		goto out;
	}

	pr_emerg("allocated %llu MB Vmalloc test memory\n",
		 vm_count * BYTE_TO_MB(mt.test_area_size));

	for (j = 0; j < max_runs && !stop_test; j++) {
		pr_emerg("starting test %llu of %d\n", j + 1, max_runs);
		for (i = 0; i < vm_count && !stop_test; i++) {
			mt.test_area = vm_list[i];
			if (j == 0)
				memset(mt.test_area, test_pattern,
				       mt.test_area_size);
			if (i == 0 && j == 0)
				dump_mem_addr(&mt, "Vmalloc start");
			ret = scan_mem(&mt);
			if (ret < 0)
				fail = ret;
		}
		sleep_and_check_testrun_state(&fail);
	}

out:
	for (i = 0; i < vm_count; i++)
		vfree(vm_list[i]);

	kfree(vm_list);
	ret = fail;

	return ret;
}

static int test_mem(void)
{
	int ret = 0, fail = 0;
	u64 i = 0;

	if (MB_TO_BYTE(free_sysmem_space) > PAGES_TO_BYTE(si_mem_available())) {
		pr_emerg("Not enough memory to test!\n");
		return -ENOMEM;
	}

	mt.test_area_size = PAGES_TO_BYTE(si_mem_available()) -
			    MB_TO_BYTE(free_sysmem_space);

	pr_emerg("allocating %llu MB for test\n",
		 BYTE_TO_MB(mt.test_area_size));
	mt.test_area = vmalloc(mt.test_area_size);
	if (!mt.test_area) {
		pr_emerg("failed to vmalloc %llu MB\n",
			 BYTE_TO_MB(mt.test_area_size));
		return -ENOMEM;
	}
	memset(mt.test_area, test_pattern, mt.test_area_size);

	meminfo_show("Meminfo during test");

	for (i = 0; i < max_runs && !stop_test; i++) {
		pr_emerg("starting test %llu of %d\n", i + 1, max_runs);
		if (i == 0)
			dump_mem_addr(&mt, "Vmalloc start");
		ret = scan_mem(&mt);
		if (ret < 0)
			fail = ret;

		sleep_and_check_testrun_state(&fail);
	}
	vfree(mt.test_area);
	ret = fail;

	return ret;
}

static int memtest_init(void)
{
	int ret = 0, fail = 0;

	meminfo_show("Meminfo before test");

	if (IS_ENABLED(CONFIG_HIGHMEM)) {
		if (test_highmem && !stop_test) {
			ret = test_highmem_arch();
			if (ret < 0)
				fail = ret;
		}
		if (test_slab && !stop_test) {
			ret = test_slab_on_highmem_arch();
			if (ret < 0)
				fail = ret;
		}
		if (test_vmalloc && !stop_test) {
			ret = test_vmalloc_on_highmem_arch();
			if (ret < 0)
				fail = ret;
		}
	} else
		fail = test_mem();

	meminfo_show("Meminfo after test");

	if (stop_test) {
		pr_emerg("Test interrupted!\n");
		return -EAGAIN;
	}

	ret = fail;
	if (ret == 0)
		pr_emerg("SUCCESS - test ends!\n");
	else
		pr_emerg("FAILED - test ends!\n");

	return ret;
}
module_init(memtest_init);

static void __exit memtest_exit(void)
{
}
module_exit(memtest_exit);

MODULE_AUTHOR("Wladislav Wiebe <wladislav.wiebe@nokia.com>");
MODULE_DESCRIPTION("Memory corruption test");
MODULE_LICENSE("GPL v2");
