/*****************************************************************************
 *    The GPL License (GPL)
 *
 *    Copyright (c) 2019 NXP
 *
 *    This program is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU General Public License
 *    as published by the Free Software Foundation; either version 2
 *    of the License, or (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You may obtain a copy of the GNU General Public License
 *    Version 2 or later at the following locations:
 *    http://www.opensource.org/licenses/gpl-license.html
 *    http://www.gnu.org/copyleft/gpl.html
 *****************************************************************************/
#include <linux/tee_drv.h>

struct tee_shm *alloc_shm(struct tee_context *ctx, size_t size);

void release_shm(struct tee_shm *shm);

void hantro_secure_regs_write(struct tee_context *ctx, uint32_t session,
		       uint32_t offset, uint32_t value);

void hantro_hwregs_write_multiple(struct tee_context *ctx, struct tee_shm* shm, uint32_t session,
		       uint32_t offset, void *regs, uint32_t size);

uint32_t hantro_secure_regs_read(struct tee_context *ctx, uint32_t session,
		       uint32_t offset);

uint32_t hantro_secure_wait(struct tee_context *ctx, uint32_t session);

struct tee_context* hantro_secure_open_context(void);

uint32_t hantro_secure_open(struct tee_context *ctx, uint32_t id);

int hantrodec_optee_match(struct tee_ioctl_version_data *ver,
				const void *data);

