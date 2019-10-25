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
#ifndef HANTRO_SECURE_H_
#define HANTRO_SECURE_H_

bool hantro_secure_alloc_shm(uint32_t Core, size_t size);

void hantro_secure_release_shm(uint32_t Core);

void hantro_secure_regs_write(uint32_t Core,
		       uint32_t offset, uint32_t value);

void hantro_secure_hwregs_write_multiple(uint32_t Core,
		       uint32_t offset, void *regs, uint32_t size);

uint32_t hantro_secure_regs_read(uint32_t Core,
		       uint32_t offset);

bool hantro_secure_wait(uint32_t Core);

bool hantro_secure_open_context(uint32_t Core);

void hantro_secure_close_context(uint32_t Core);

bool hantro_secure_open_session(uint32_t Core);

void hantro_secure_close_session(uint32_t Core);

#endif // HANTRO_SECURE_H_
