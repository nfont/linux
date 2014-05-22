/*
 * pseries Memory Hotplug infrastructure.
 *
 * Copyright (C) 2008 Badari Pulavarty, IBM Corporation
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/memblock.h>
#include <linux/vmalloc.h>
#include <linux/memory.h>
#include <linux/memory_hotplug.h>
#include <linux/slab.h>

#include <asm/firmware.h>
#include <asm/machdep.h>
#include <asm/sparsemem.h>
#include <asm/prom.h>
#include <asm/rtas.h>

#include "pseries.h"

DEFINE_MUTEX(dlpar_mem_mutex);

static unsigned long get_memblock_size(void)
{
	struct device_node *np;
	unsigned int memblock_size = MIN_MEMORY_BLOCK_SIZE;
	struct resource r;

	np = of_find_node_by_path("/ibm,dynamic-reconfiguration-memory");
	if (np) {
		const __be64 *size;

		size = of_get_property(np, "ibm,lmb-size", NULL);
		if (size)
			memblock_size = be64_to_cpup(size);
		of_node_put(np);
	} else  if (machine_is(pseries)) {
		/* This fallback really only applies to pseries */
		unsigned int memzero_size = 0;

		np = of_find_node_by_path("/memory@0");
		if (np) {
			if (!of_address_to_resource(np, 0, &r))
				memzero_size = resource_size(&r);
			of_node_put(np);
		}

		if (memzero_size) {
			/* We now know the size of memory@0, use this to find
			 * the first memoryblock and get its size.
			 */
			char buf[64];

			sprintf(buf, "/memory@%x", memzero_size);
			np = of_find_node_by_path(buf);
			if (np) {
				if (!of_address_to_resource(np, 0, &r))
					memblock_size = resource_size(&r);
				of_node_put(np);
			}
		}
	}
	return memblock_size;
}

/* WARNING: This is going to override the generic definition whenever
 * pseries is built-in regardless of what platform is active at boot
 * time. This is fine for now as this is the only "option" and it
 * should work everywhere. If not, we'll have to turn this into a
 * ppc_md. callback
 */
unsigned long memory_block_size_bytes(void)
{
	return get_memblock_size();
}

static struct property *dlpar_clone_drconf_property(struct device_node *dn)
{
	struct property *prop, *new_prop;

	prop = of_find_property(dn, "ibm,dynamic-memory", NULL);
	if (!prop)
		return NULL;

	new_prop = kzalloc(sizeof(*new_prop), GFP_KERNEL);
	if (!new_prop)
		return NULL;

	new_prop->name = kstrdup(prop->name, GFP_KERNEL);
	new_prop->value = kmalloc(prop->length + 1, GFP_KERNEL);
	if (!new_prop->name || !new_prop->value) {
		kfree(new_prop->name);
		kfree(new_prop->value);
		kfree(new_prop);
		return NULL;
	}

	memcpy(new_prop->value, prop->value, prop->length);
	new_prop->length = prop->length;
	*(((char *)new_prop->value) + new_prop->length) = 0;

	return new_prop;
}

static int lmb_is_removable(struct of_drconf_cell *lmb)
{
	int i, scns_per_block;
	int rc = 1;
	unsigned long pfn, block_sz;
	uint64_t base_addr;

	base_addr = lmb->base_addr;
	block_sz = memory_block_size_bytes();
	scns_per_block = block_sz / MIN_MEMORY_BLOCK_SIZE;

	for (i = 0; i < scns_per_block; i++) {
		pfn = PFN_DOWN(base_addr);
		if (!pfn_present(pfn))
			continue;
	
		rc &= is_mem_section_removable(pfn, PAGES_PER_SECTION);
		base_addr += MIN_MEMORY_BLOCK_SIZE;
	}

	return rc;
}

static int lmb_is_usable(struct pseries_hp_elog *hp_elog,
			 struct of_drconf_cell *lmb)
{
	if (hp_elog->id_type == HP_ELOG_ID_DRC_INDEX
	    && hp_elog->_drc_u.drc_index == lmb->drc_index) {
		return 1;
	} else {
		if (hp_elog->action == HP_ELOG_ACTION_ADD
		    && !(lmb->flags & DRCONF_MEM_ASSIGNED))
			return 1;

		if (hp_elog->action == HP_ELOG_ACTION_REMOVE
		    && lmb->flags & DRCONF_MEM_ASSIGNED)
			return lmb_is_removable(lmb);
	}

	return 0;
}

static struct memory_block *lmb_to_memblock(struct of_drconf_cell *lmb)
{
	unsigned long section_nr;
	struct mem_section *mem_sect;
	struct memory_block *mem_block;

	section_nr = pfn_to_section_nr(PFN_DOWN(lmb->base_addr));
	mem_sect = __nr_to_section(section_nr);

	mem_block = find_memory_block(mem_sect);
	return mem_block;
}

static int dlpar_add_one_lmb(struct of_drconf_cell *lmb)
{
	struct memory_block *mem_block;
	u64 phys_addr;
	unsigned long pages_per_block;
	unsigned long block_sz;
	int nid, sections_per_block;
	int rc;

	phys_addr = lmb->base_addr;
	block_sz = memory_block_size_bytes();
	sections_per_block = block_sz / MIN_MEMORY_BLOCK_SIZE;
	pages_per_block = PAGES_PER_SECTION * sections_per_block;

	if (phys_addr & ((pages_per_block << PAGE_SHIFT) - 1))
		return -EINVAL;

	nid = memory_add_physaddr_to_nid(phys_addr);
	rc = add_memory(nid, phys_addr, block_sz);
	if (rc)
		return rc;

	rc = memblock_add(lmb->base_addr, block_sz);
	if (rc) {
		remove_memory(nid, phys_addr, block_sz);
		return rc;
	}

	mem_block = lmb_to_memblock(lmb);
	if (!mem_block) {
		remove_memory(nid, phys_addr, block_sz);
		return -EINVAL;
	}

	rc = device_online(&mem_block->dev);
	put_device(&mem_block->dev);
	if (rc)
		remove_memory(nid, phys_addr, block_sz);

	return rc;
}

static int dlpar_memory_add(struct pseries_hp_elog *hp_elog)
{
	struct of_drconf_cell *lmb;
	struct device_node *dn;
	struct property *prop;
	uint32_t *p, entries;
	int i, lmbs_to_add;
	int lmbs_added = 0;
	int rc = -EINVAL;

	if (hp_elog->id_type == HP_ELOG_ID_DRC_COUNT)
		lmbs_to_add = hp_elog->_drc_u.drc_count;
	else
		lmbs_to_add = 1;

	dn = of_find_node_by_path("/ibm,dynamic-reconfiguration-memory");
	if (!dn)
		return -EINVAL;

	prop = dlpar_clone_drconf_property(dn);
	if (!prop) {
		of_node_put(dn);
		return -EINVAL;
	}

        p = prop->value;
        entries = *p++;
        lmb = (struct of_drconf_cell *)p;

	for (i = 0; i < entries; i++, lmb++) {
		if (lmbs_to_add == lmbs_added)
			break;

		if (!lmb_is_usable(hp_elog, lmb))
			continue;

		rc = dlpar_acquire_drc(lmb->drc_index);
		if (rc)
			continue;

		rc = dlpar_add_one_lmb(lmb);

		lmb->flags |= DRCONF_MEM_ASSIGNED;
		lmbs_added++;
	}

	if (lmbs_added)
		rc = of_update_property(dn, prop);
	else
		kfree(prop);

	of_node_put(dn);
	return rc ? rc : lmbs_added;
}

#ifdef CONFIG_MEMORY_HOTREMOVE
static int pseries_remove_memory(u64 start, u64 size)
{
	int ret;

	/* Remove htab bolted mappings for this section of memory */
	start = (unsigned long)__va(start);
	ret = remove_section_mapping(start, start + size);

	/* Ensure all vmalloc mappings are flushed in case they also
	 * hit that section of memory
	 */
	vm_unmap_aliases();

	return ret;
}

static int dlpar_remove_one_lmb(struct of_drconf_cell *lmb)
{
	struct memory_block *mem_block;
	unsigned long block_sz;
	int nid, rc;

	block_sz = memory_block_size_bytes();
	nid = memory_add_physaddr_to_nid(lmb->base_addr);

	if (!pfn_valid(lmb->base_addr >> PAGE_SHIFT)) {
		memblock_remove(lmb->base_addr, block_sz);
		return 0;
	}

	mem_block = lmb_to_memblock(lmb);
	if (!mem_block)
		return -EINVAL;

	rc = device_offline(&mem_block->dev);
	put_device(&mem_block->dev);
	if (rc)
		return rc;

	remove_memory(nid, lmb->base_addr, block_sz);
	memblock_remove(lmb->base_addr, block_sz);

	return 0;
}

static int dlpar_memory_remove(struct pseries_hp_elog *hp_elog)
{
	struct of_drconf_cell *lmb;
	struct device_node *dn;
	struct property *prop;
	int lmbs_to_remove, lmbs_removed = 0;
	int i, rc, entries;
	uint32_t *p;

	if (hp_elog->id_type == HP_ELOG_ID_DRC_COUNT)
		lmbs_to_remove = hp_elog->_drc_u.drc_count;
	else
		lmbs_to_remove = 1;

	dn = of_find_node_by_path("/ibm,dynamic-reconfiguration-memory");
	if (!dn)
		return -EINVAL;

	prop = dlpar_clone_drconf_property(dn);
	if (!prop) {
		of_node_put(dn);
		return -EINVAL;
	}

        p = prop->value;
        entries = *p++;
        lmb = (struct of_drconf_cell *)p;

	for (i = 0; i < entries; i++, lmb++) {
		if (lmbs_to_remove == lmbs_removed)
			break;

		if (!lmb_is_usable(hp_elog, lmb))
			continue;

		rc = dlpar_remove_one_lmb(lmb);
		if (rc)
			continue;

		rc = dlpar_release_drc(lmb->drc_index);
		if (rc) {
			dlpar_add_one_lmb(lmb);
			continue;
		}

		lmb->flags &= ~DRCONF_MEM_ASSIGNED;
		lmbs_removed++;
	}

	if (lmbs_removed)
		rc = of_update_property(dn, prop);
	else
		kfree(prop);

	of_node_put(dn);
	return rc;
}

static int pseries_remove_memblock(unsigned long base, unsigned int memblock_size)
{
	unsigned long block_sz, start_pfn;
	int sections_per_block;
	int i, nid;

	start_pfn = base >> PAGE_SHIFT;

	lock_device_hotplug();

	if (!pfn_valid(start_pfn))
		goto out;

	block_sz = memory_block_size_bytes();
	sections_per_block = block_sz / MIN_MEMORY_BLOCK_SIZE;
	nid = memory_add_physaddr_to_nid(base);

	for (i = 0; i < sections_per_block; i++) {
		remove_memory(nid, base, MIN_MEMORY_BLOCK_SIZE);
		base += MIN_MEMORY_BLOCK_SIZE;
	}

out:
	/* Update memory regions for memory remove */
	memblock_remove(base, memblock_size);
	unlock_device_hotplug();
	return 0;
}

static int pseries_remove_mem_node(struct device_node *np)
{
	const char *type;
	const unsigned int *regs;
	unsigned long base;
	unsigned int lmb_size;
	int ret = -EINVAL;

	/*
	 * Check to see if we are actually removing memory
	 */
	type = of_get_property(np, "device_type", NULL);
	if (type == NULL || strcmp(type, "memory") != 0)
		return 0;

	/*
	 * Find the bae address and size of the memblock
	 */
	regs = of_get_property(np, "reg", NULL);
	if (!regs)
		return ret;

	base = *(unsigned long *)regs;
	lmb_size = regs[3];

	pseries_remove_memblock(base, lmb_size);
	return 0;
}
#else
static inline int dlpar_memory_remove(struct pseries_hp_elog *hp_elog)
{
	return -EOPNOTSUPP;
}
static inline int pseries_remove_memblock(unsigned long base,
					  unsigned int memblock_size)
{
	return -EOPNOTSUPP;
}
static inline int pseries_remove_mem_node(struct device_node *np)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_MEMORY_HOTREMOVE */

int dlpar_memory(struct pseries_hp_elog *hp_elog)
{
	int rc = 0;

	mutex_lock(&dlpar_mem_mutex);

	switch (hp_elog->action) {
	case HP_ELOG_ACTION_ADD:
		rc = dlpar_memory_add(hp_elog);
		break;
	case HP_ELOG_ACTION_REMOVE:
		rc = dlpar_memory_remove(hp_elog);
		break;
	}

	mutex_unlock(&dlpar_mem_mutex);
	return rc;
}

static int pseries_add_mem_node(struct device_node *np)
{
	const char *type;
	const unsigned int *regs;
	unsigned long base;
	unsigned int lmb_size;
	int ret = -EINVAL;

	/*
	 * Check to see if we are actually adding memory
	 */
	type = of_get_property(np, "device_type", NULL);
	if (type == NULL || strcmp(type, "memory") != 0)
		return 0;

	/*
	 * Find the base and size of the memblock
	 */
	regs = of_get_property(np, "reg", NULL);
	if (!regs)
		return ret;

	base = *(unsigned long *)regs;
	lmb_size = regs[3];

	/*
	 * Update memory region to represent the memory add
	 */
	ret = memblock_add(base, lmb_size);
	return (ret < 0) ? -EINVAL : 0;
}

static int pseries_memory_notifier(struct notifier_block *nb,
				   unsigned long action, void *node)
{
	int err = 0;

	switch (action) {
	case OF_RECONFIG_ATTACH_NODE:
		err = pseries_add_mem_node(node);
		break;
	case OF_RECONFIG_DETACH_NODE:
		err = pseries_remove_mem_node(node);
		break;
	}

	return notifier_from_errno(err);
}

static struct notifier_block pseries_mem_nb = {
	.notifier_call = pseries_memory_notifier,
};

static int __init pseries_memory_hotplug_init(void)
{
	if (firmware_has_feature(FW_FEATURE_LPAR))
		of_reconfig_notifier_register(&pseries_mem_nb);

#ifdef CONFIG_MEMORY_HOTREMOVE
	ppc_md.remove_memory = pseries_remove_memory;
#endif

	return 0;
}
machine_device_initcall(pseries, pseries_memory_hotplug_init);
