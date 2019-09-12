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

/** @brief  PTA UUID generated at https://www.gguid.com/ */
#define PTA_HANTRO_VPU_PTA_UUID {0xf45a8128,0x23ff,0x4949,{0x98,0xa4,0x58,0xcb,0x8a,0xef,0x5a,0x75}}

#define PTA_HANTRO_VPU_CMD_WAIT				0
#define PTA_HANTRO_VPU_CMD_READ				1
#define PTA_HANTRO_VPU_CMD_WRITE			2
#define PTA_HANTRO_VPU_CMD_WRITE_MULTIPLE	3

typedef struct {
       uint32_t timeLow;
       uint16_t timeMid;
       uint16_t timeHiAndVersion;
       uint8_t clockSeqAndNode[8];
} RTC_UUID;

struct tee_shm *alloc_shm(struct tee_context *ctx, size_t size)
{
	if (ctx == NULL)
		return NULL;

	return tee_shm_alloc(ctx,size,TEE_SHM_MAPPED);
}

void release_shm(struct tee_shm *shm)
{
	if (shm)
		tee_shm_free(shm);
}

void hantro_secure_regs_write(struct tee_context *ctx, uint32_t session,
		       uint32_t offset, uint32_t value)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];

	if (ctx == NULL)
		return;

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

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

void hantro_hwregs_write_multiple(struct tee_context *ctx, struct tee_shm* shm, uint32_t session,
		       uint32_t offset, void *regs, uint32_t size)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];

	if (ctx == NULL)
		return;
	// check buffer overflow
	if (offset + size < offset)
		return;

	memcpy(tee_shm_get_va(shm,offset),regs + offset,size);
	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

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

uint32_t hantro_secure_regs_read(struct tee_context *ctx, uint32_t session,
		       uint32_t offset)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];

	if (ctx == NULL)
		return 0;

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

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

uint32_t hantro_secure_wait(struct tee_context *ctx, uint32_t session)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];

	if (ctx == NULL)
		return -1;

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	/* Invoke PTA_HANTRO_VPU_CMD_WRITE function */
	inv_arg.func = PTA_HANTRO_VPU_CMD_WAIT;
	inv_arg.session = session;
	inv_arg.num_params = 4;

	/* Fill invoke cmd params */
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[0].u.value.a = 200; // 200ms timeout

	ret = tee_client_invoke_func(ctx, &inv_arg, param);
	if ((ret < 0) || inv_arg.ret) {
		pr_err("PTA_HANTRO_VPU_CMD_WAIT invoke function err: 0x%08X 0x%08X\n",
		       ret,inv_arg.ret);
		return -1;
	}
	return 0;
}

static int hantrodec_optee_match(struct tee_ioctl_version_data *ver,
				const void *data)
{
	if (ver->impl_id == TEE_IMPL_ID_OPTEE)
		return 1;
	else
		return 0;
}

struct tee_context* hantro_secure_open_context(void)
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
		ctx = NULL;
	}

	return ctx;
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

uint32_t hantro_secure_open(struct tee_context* ctx, uint32_t id)
{
	const RTC_UUID pta_uuid = PTA_HANTRO_VPU_PTA_UUID;
	struct tee_ioctl_open_session_arg sess_arg;
	struct tee_param param[4];
	struct tee_param *params = NULL;
	int result;

	if (ctx == NULL)
		return 0;

	memset(&sess_arg, 0, sizeof(sess_arg));
	memset(&param, 0, sizeof(param));

	/* Open session with pseudo TA */
	uuid_to_octets(sess_arg.uuid, &pta_uuid);
	sess_arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;

	if (id != 0xFFFFFFFF)
	{
		sess_arg.num_params = 4;

		/* Fill invoke cmd params */
		param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
		param[0].u.value.a = id;

		params = param;
	} else {
		sess_arg.num_params = 0;
	}

	result = tee_client_open_session(ctx, &sess_arg, params);
	if ((result < 0) || sess_arg.ret) {
		pr_err("unable to open pta session 0x%08X\n",sess_arg.ret);
		return 0;
	}

	return sess_arg.session;
}
