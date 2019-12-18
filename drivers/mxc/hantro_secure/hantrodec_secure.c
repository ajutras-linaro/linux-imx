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
#include <linux/time.h>

/** @brief  PTA UUID generated at https://www.gguid.com/ */
#define PTA_HANTRO_VPU_PTA_UUID {0xf45a8128,0x23ff,0x4949,{0x98,0xa4,0x58,0xcb,0x8a,0xef,0x5a,0x75}}

#define PTA_HANTRO_VPU_CMD_WAIT				0
#define PTA_HANTRO_VPU_CMD_READ				1
#define PTA_HANTRO_VPU_CMD_WRITE			2
#define PTA_HANTRO_VPU_CMD_WRITE_MULTIPLE	3
#define PTA_HANTRO_VPU_CMD_READ_MULTIPLE	4

#define HXDEC_MAX_CORES             	    2

typedef struct {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
} RTC_UUID;

typedef struct {
	struct tee_context *ctx;
	uint32_t session;
	struct tee_shm* shm;
} hantro_secure_core;

static hantro_secure_core Cores[HXDEC_MAX_CORES] = { 0 };
static struct tee_context *base_ctx = NULL;
static uint32_t base_session = 0;

#ifdef PERF_COUNTERS
static uint32_t nIT = 0;
static long long nTimer = 0;
#endif

/*
	Utility functions
*/
#ifdef PERF_COUNTERS
static long long get_timer(void)
{
	struct timeval cur;

	do_gettimeofday(&cur);

	return timeval_to_ns(&cur);
}
#endif

static int hantrodec_optee_match(struct tee_ioctl_version_data *ver,
				const void *data)
{
	if (ver->impl_id == TEE_IMPL_ID_OPTEE)
		return 1;
	else
		return 0;
}

static void uuid_to_octets(uint8_t d[TEE_IOCTL_UUID_LEN], const RTC_UUID *s)
{
	d[0] = s->timeLow >> 24;
	d[1] = s->timeLow >> 16;
	d[2] = s->timeLow >> 8;
	d[3] = s->timeLow;
	d[4] = s->timeMid >> 8;
	d[5] = s->timeMid;
	d[6] = s->timeHiAndVersion >> 8;
	d[7] = s->timeHiAndVersion;
	memcpy(d + 8, s->clockSeqAndNode, sizeof(s->clockSeqAndNode));
}

static struct tee_context* get_context(uint32_t Core)
{
	if (Core < HXDEC_MAX_CORES)
		return Cores[Core].ctx;
	if (Core == 0xFFFFFFFF)
		return base_ctx;

	pr_err("%s no context found [%d]\n",__func__,Core);
	return NULL;
}

static void set_context(uint32_t Core, struct tee_context *ctx)
{
	if (Core < HXDEC_MAX_CORES)
		Cores[Core].ctx = ctx;
	if (Core == 0xFFFFFFFF)
		base_ctx = ctx;
}

static uint32_t get_session(uint32_t Core)
{
	if (Core < HXDEC_MAX_CORES)
		return Cores[Core].session;
	if (Core == 0xFFFFFFFF)
		return base_session;

	pr_err("%s no session found [%d]\n",__func__,Core);
	return 0;
}

static void set_session(uint32_t Core, uint32_t session)
{
	if (Core < HXDEC_MAX_CORES)
		Cores[Core].session = session;
	if (Core == 0xFFFFFFFF)
		base_session = session;
}

static struct tee_shm* get_shm(uint32_t Core)
{
	if (Core < HXDEC_MAX_CORES)
		return Cores[Core].shm;

	pr_err("%s no shared mem found [%d]\n",__func__,Core);
	return NULL;
}

static void set_shm(uint32_t Core, struct tee_shm *shm)
{
	if (Core < HXDEC_MAX_CORES)
		Cores[Core].shm = shm;
}

/*
	API functions
*/

bool hantro_secure_alloc_shm(uint32_t Core, size_t size)
{
	struct tee_context *ctx;

	ctx = get_context(Core);
	if (ctx == NULL)
		return false;

	set_shm(Core, tee_shm_alloc(ctx,size,TEE_SHM_MAPPED));
	return true;
}

void hantro_secure_release_shm(uint32_t Core)
{
	struct tee_shm *shm;

	shm = get_shm(Core);
	if (shm)
		tee_shm_free(shm);
}

void hantro_secure_regs_write(uint32_t Core,
		       uint32_t offset, uint32_t value)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg = { 0 };
	struct tee_param param[4] = { 0 };
	struct tee_context *ctx;
	uint32_t session;

	ctx = get_context(Core);
	if (ctx == NULL)
		return;

	session = get_session(Core);

	/* Invoke PTA_HANTRO_VPU_CMD_WRITE function */
	inv_arg.func = PTA_HANTRO_VPU_CMD_WRITE;
	inv_arg.session = session;
	inv_arg.num_params = 4;

	/* Fill invoke cmd params */
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[0].u.value.a = offset;
	param[0].u.value.b = value;

	ret = tee_client_invoke_func(ctx, &inv_arg, param);
	if ((ret < 0) || inv_arg.ret) {
		pr_err("PTA_HANTRO_VPU_CMD_WRITE invoke function err: 0x%08X 0x%08X\n",
		       ret,inv_arg.ret);
	}
}

void hantro_secure_hwregs_write_multiple(uint32_t Core,
		       uint32_t offset, void *regs, uint32_t size)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg = { 0 };
	struct tee_param param[4] = { 0 };
	struct tee_context *ctx;
	struct tee_shm* shm;
	uint32_t session;

	ctx = get_context(Core);

	if (ctx == NULL)
		return;
	if (regs == NULL)
		return;
	// check buffer overflow
	if (offset + size < offset)
		return;

	session = get_session(Core);
	shm = get_shm(Core);

	memcpy(tee_shm_get_va(shm,offset),regs + offset,size);

	/* Invoke PTA_HANTRO_VPU_CMD_WRITE function */
	inv_arg.func = PTA_HANTRO_VPU_CMD_WRITE_MULTIPLE;
	inv_arg.session = session;
	inv_arg.num_params = 4;

	/* Fill invoke cmd params */
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[0].u.value.a = offset;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
	param[1].u.memref.shm_offs = offset;
	param[1].u.memref.size = size;
	param[1].u.memref.shm = shm;

	ret = tee_client_invoke_func(ctx, &inv_arg, param);
	if ((ret < 0) || inv_arg.ret) {
		pr_err("PTA_HANTRO_VPU_CMD_WRITE_MULTIPLE invoke function err: 0x%08X 0x%08X\n",
		       ret,inv_arg.ret);
	}
}

void hantro_secure_hwregs_read_multiple(uint32_t Core,
		       uint32_t offset, void *regs, uint32_t size)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg = { 0 };
	struct tee_param param[4] = { 0 };
	struct tee_context *ctx;
	struct tee_shm* shm;
	uint32_t session;

	ctx = get_context(Core);

	if (ctx == NULL)
		return;
	if (regs == NULL)
		return;
	// check buffer overflow
	if (offset + size < offset)
		return;

	session = get_session(Core);
	shm = get_shm(Core);

	/* Invoke PTA_HANTRO_VPU_CMD_READ_MULTIPLE function */
	inv_arg.func = PTA_HANTRO_VPU_CMD_READ_MULTIPLE;
	inv_arg.session = session;
	inv_arg.num_params = 4;

	/* Fill invoke cmd params */
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[0].u.value.a = offset;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
	param[1].u.memref.shm_offs = offset;
	param[1].u.memref.size = size;
	param[1].u.memref.shm = shm;

	ret = tee_client_invoke_func(ctx, &inv_arg, param);
	if ((ret < 0) || inv_arg.ret) {
		pr_err("PTA_HANTRO_VPU_CMD_READ_MULTIPLE invoke function err: 0x%08X 0x%08X\n",
		       ret,inv_arg.ret);
	}

	memcpy(regs + offset, tee_shm_get_va(shm,offset),size);
}

uint32_t hantro_secure_regs_read(uint32_t Core,
		       uint32_t offset)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg = { 0 };
	struct tee_param param[4] = { 0 };
	struct tee_context *ctx;
	uint32_t session;

	ctx = get_context(Core);

	if (ctx == NULL)
		return 0;

	session = get_session(Core);

	/* Invoke PTA_HANTRO_VPU_CMD_READ function */
	inv_arg.func = PTA_HANTRO_VPU_CMD_READ;
	inv_arg.session = session;
	inv_arg.num_params = 4;

	/* Fill invoke cmd params */
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT;
	param[0].u.value.a = offset;

	ret = tee_client_invoke_func(ctx, &inv_arg, param);
	if ((ret < 0) || inv_arg.ret) {
		pr_err("PTA_HANTRO_VPU_CMD_READ invoke function err: 0x%08X 0x%08X\n",
		       ret,inv_arg.ret);
		return 0;
	}
	return param[1].u.value.a;
}

bool hantro_secure_wait(uint32_t Core)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg = { 0 };
	struct tee_param param[4] = { 0 };

	struct tee_context *ctx;
	uint32_t session;

	ctx = get_context(Core);

	if (ctx == NULL)
		return false;

	session = get_session(Core);

	/* Invoke PTA_HANTRO_VPU_CMD_WAIT function */
	inv_arg.func = PTA_HANTRO_VPU_CMD_WAIT;
	inv_arg.session = session;
	inv_arg.num_params = 4;

	/* Fill invoke cmd params */
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT;
	param[0].u.value.a = 200; // 200ms timeout

	ret = tee_client_invoke_func(ctx, &inv_arg, param);
	if ((ret < 0) || inv_arg.ret) {
		pr_err("PTA_HANTRO_VPU_CMD_WAIT invoke function err: 0x%08X 0x%08X\n",
		       ret,inv_arg.ret);
		return false;
	}

#ifdef PERF_COUNTERS
	pr_info("VPU response time %d us",param[0].u.value.b);
	nIT++;
	if (get_timer() - nTimer > NSEC_PER_SEC)
	{
		nTimer = get_timer();
		pr_info("%ld secure wait / seconds %d",nTimer,nIT);
		nIT = 0;
	}
#endif

	return true;
}

bool hantro_secure_open_context(uint32_t Core)
{
	struct tee_context *ctx;
	struct tee_ioctl_version_data vers = {
		.impl_id = TEE_OPTEE_CAP_TZ,
		.impl_caps = TEE_IMPL_ID_OPTEE,
		.gen_caps = TEE_GEN_CAP_GP,
	};

	ctx = tee_client_open_context(NULL, hantrodec_optee_match,
					     NULL, &vers);

	if (IS_ERR(ctx))
	{
		pr_err("unable to open tee ctx %p\n",(void*)ctx);
		return false;
	}

	set_context(Core,ctx);

	return true;
}

void hantro_secure_close_context(uint32_t Core)
{
	struct tee_context *ctx;

	ctx = get_context(Core);
	if (ctx)
	{
		tee_client_close_context(ctx);
		set_context(Core,NULL);
	}
}

bool hantro_secure_open_session(uint32_t Core)
{
	const RTC_UUID pta_uuid = PTA_HANTRO_VPU_PTA_UUID;
	struct tee_ioctl_open_session_arg sess_arg = { 0 };
	struct tee_param param[4] = { 0 };
	struct tee_param *params = NULL;
	int result;
	struct tee_context *ctx;

	ctx = get_context(Core);
	if (ctx == NULL)
		return false;

	/* Open session with pseudo TA */
	uuid_to_octets(sess_arg.uuid, &pta_uuid);
	sess_arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;

	if (Core != 0xFFFFFFFF)
	{
		sess_arg.num_params = 4;

		/* Fill invoke cmd params */
		param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
		param[0].u.value.a = Core;

		params = param;
	} else {
		sess_arg.num_params = 0;
	}

	result = tee_client_open_session(ctx, &sess_arg, params);
	if ((result < 0) || sess_arg.ret) {
		pr_err("unable to open pta session 0x%08X\n",sess_arg.ret);
		return -1;
	}

	set_session(Core,sess_arg.session);

	return true;
}

void hantro_secure_close_session(uint32_t Core)
{
	struct tee_context *ctx;
	uint32_t session;

	ctx = get_context(Core);

	if (ctx)
	{
		session = get_session(Core);

		tee_client_close_session(ctx,session);

		set_session(Core,0);
	}
}

