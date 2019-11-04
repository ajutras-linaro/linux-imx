/*
 * Copyright 2019 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _HANTRODEC_SECURE_H_
#define _HANTRODEC_SECURE_H_

bool hantro_secure_alloc_shm(uint32_t Core, size_t size);

void hantro_secure_release_shm(uint32_t Core);

void hantro_secure_regs_write(uint32_t Core,
		       uint32_t offset, uint32_t value);

void hantro_secure_hwregs_write_multiple(uint32_t Core,
		       uint32_t offset, void *regs, uint32_t size);

uint32_t hantro_secure_regs_read(uint32_t Core,
		       uint32_t offset);

void hantro_secure_hwregs_read_multiple(uint32_t Core,
		       uint32_t offset, void *regs, uint32_t size);

bool hantro_secure_wait(uint32_t Core);

bool hantro_secure_open_context(uint32_t Core);

void hantro_secure_close_context(uint32_t Core);

bool hantro_secure_open_session(uint32_t Core);

void hantro_secure_close_session(uint32_t Core);

#endif /* !_HANTRODEC_SECURE_H_ */
