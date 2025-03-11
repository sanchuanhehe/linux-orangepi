/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Clang Control Flow Integrity (CFI) support.
 *
<<<<<<< HEAD
 * Copyright (C) 2019 Google LLC
=======
 * Copyright (C) 2021 Google LLC
>>>>>>> ohos/OpenHarmony-5.0.2-Release
 */
#ifndef _LINUX_CFI_H
#define _LINUX_CFI_H

#ifdef CONFIG_CFI_CLANG
typedef void (*cfi_check_fn)(uint64_t id, void *ptr, void *diag);

/* Compiler-generated function in each module, and the kernel */
extern void __cfi_check(uint64_t id, void *ptr, void *diag);

/*
 * Force the compiler to generate a CFI jump table entry for a function
 * and store the jump table address to __cfi_jt_<function>.
 */
<<<<<<< HEAD
#define __CFI_ADDRESSABLE(fn) \
	const void* __cfi_jt_ ## fn __visible = (void *)&fn;
=======
#define __CFI_ADDRESSABLE(fn, __attr) \
	const void *__cfi_jt_ ## fn __visible __attr = (void *)&fn
>>>>>>> ohos/OpenHarmony-5.0.2-Release

#ifdef CONFIG_CFI_CLANG_SHADOW

extern void cfi_module_add(struct module *mod, unsigned long base_addr);
extern void cfi_module_remove(struct module *mod, unsigned long base_addr);

#else

static inline void cfi_module_add(struct module *mod, unsigned long base_addr) {}
static inline void cfi_module_remove(struct module *mod, unsigned long base_addr) {}

#endif /* CONFIG_CFI_CLANG_SHADOW */

#else /* !CONFIG_CFI_CLANG */

<<<<<<< HEAD
#define __CFI_ADDRESSABLE(fn)
=======
#define __CFI_ADDRESSABLE(fn, __attr)
>>>>>>> ohos/OpenHarmony-5.0.2-Release

#endif /* CONFIG_CFI_CLANG */

#endif /* _LINUX_CFI_H */
