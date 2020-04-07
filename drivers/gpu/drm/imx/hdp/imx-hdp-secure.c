/*
 * Copyright 2017-2019 NXP
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/tee_drv.h>

#include <drm/drmP.h>

#include <imx-hdp-secure.h>

/** @brief  PTA UUID generated at https://www.gguid.com/ */
/* aaf0c79e-5ff4-4f8c-bef4-042337f0d418 */
#define HDCP_PTA_UUID {0xaaf0c79e,0x5ff4,0x4f8c,{0xbe,0xf4,0x04,0x23,0x37,0xf0,0xd4,0x18}}

#define PTA_HDCP_CMD_WRITE 		0
#define PTA_HDCP_CMD_READ 		1

typedef struct
{
	struct tee_context *ctx;
	uint32_t session;
} shdcp_bus;

static shdcp_bus hdcp_bus[PTA_HDCP_MAX_BUSID];

typedef struct {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
} RTC_UUID;

/*****************************************************************************
 * Helpers to manage access to the pseudo OPTEE TA protecting HDCP registers *
 *****************************************************************************/

static int imx_hdcp_optee_match(struct tee_ioctl_version_data *ver, const void *data)
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

static uint32_t imx_hdcp_secure_get_session(uint32_t busId)
{
	if (busId >= PTA_HDCP_HDP_BUSID && busId < PTA_HDCP_MAX_BUSID)
	{
		return hdcp_bus[busId].session;
	}
	pr_err("%s busId %d is not supported\n",__func__, busId);
	return 0;
}

static void imx_hdcp_secure_set_session(uint32_t busId, uint32_t session)
{
	DRM_WARN("imx_hdcp_secure_set_session bus Id %d session 0x%08X \n", busId, session);

	if (busId >= PTA_HDCP_HDP_BUSID && busId < PTA_HDCP_MAX_BUSID)
	{
		hdcp_bus[busId].session = session;
	}
	else
	{
		pr_err("%s busId %d is not supported\n",__func__, busId);
	}
}

static struct tee_context* imx_hdcp_secure_get_context(uint32_t busId)
{
	if (busId >= PTA_HDCP_HDP_BUSID && busId < PTA_HDCP_MAX_BUSID)
	{
		return hdcp_bus[busId].ctx;
	}
	pr_err("%s busId %d is not supported\n",__func__, busId);
	return NULL;
}

static void imx_hdcp_secure_set_context(uint32_t busId, struct tee_context *ctx)
{
	if (busId >= PTA_HDCP_HDP_BUSID && busId < PTA_HDCP_MAX_BUSID)
	{
		hdcp_bus[busId].ctx = ctx;
	}
	else
	{
		pr_err("%s busId %d is not supported\n",__func__, busId);
	}
}

/*****************
 * API functions *
 *****************/

void imx_hdcp_secure_register_write(uint32_t busId, uint32_t offset, uint32_t value)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];
	struct tee_context *ctx;
	uint32_t session;

	if (busId < PTA_HDCP_HDP_BUSID || busId >= PTA_HDCP_MAX_BUSID)
	{
		pr_err("%s busId %d is not supported\n",__func__, busId);
		return;
	}

	ctx = imx_hdcp_secure_get_context(busId);
	if (ctx == NULL)
	{
		pr_err("%s invalid tee context\n",__func__);
		return;
	}

	session = imx_hdcp_secure_get_session(busId);
        if (session == 0)
	{
		pr_err("%s invalid tee session\n",__func__);
		return;
	}
	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	/* Invoke PTA_HDCP_CMD_WRITE function */
	inv_arg.func = PTA_HDCP_CMD_WRITE;
	inv_arg.session = session;
	inv_arg.num_params = 4;

	/* Fill invoke cmd params */
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[0].u.value.a = busId;
	param[1].u.value.a = offset;
	param[1].u.value.b = value;

	ret = tee_client_invoke_func(ctx, &inv_arg, param);
	if ((ret < 0) || inv_arg.ret)
	{
		pr_err("PTA_HDCP_CMD_WRITE invoke function err: 0x%08X 0x%08X\n", ret, inv_arg.ret);
	}
}

uint32_t imx_hdcp_secure_register_read(uint32_t busId, uint32_t offset)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];
	struct tee_context *ctx;
	uint32_t session;

	if (busId < PTA_HDCP_HDP_BUSID || busId >= PTA_HDCP_MAX_BUSID)
	{
		pr_err("%s busId %d is not supported\n",__func__, busId);
		return 0;
	}

	ctx = imx_hdcp_secure_get_context(busId);
	if (ctx == NULL)
	{
		pr_err("%s invalid tee context\n",__func__);
		return 0;
	}

	session = imx_hdcp_secure_get_session(busId);
	if (session == 0)
	{
		pr_err("%s invalid tee session\n",__func__);
		return 0;
	}
	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	/* Invoke PTA_HDCP_CMD_READ function */
	inv_arg.func = PTA_HDCP_CMD_READ;
	inv_arg.session = session;
	inv_arg.num_params = 4;

	/* Fill invoke cmd params */
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT;
	param[0].u.value.a = busId;
	param[0].u.value.b = offset;

	ret = tee_client_invoke_func(ctx, &inv_arg, param);
	if ((ret < 0) || inv_arg.ret)
	{
		pr_err("PTA_HDCP_CMD_READ invoke function err: 0x%08X 0x%08X\n", ret,inv_arg.ret);
		return 0;
	}
	return param[1].u.value.a;
}

bool imx_hdcp_secure_open_context(uint32_t busId)
{
	struct tee_context *ctx;
	struct tee_ioctl_version_data vers = {
		.impl_id = TEE_OPTEE_CAP_TZ,
		.impl_caps = TEE_IMPL_ID_OPTEE,
		.gen_caps = TEE_GEN_CAP_GP,
	};

	DRM_INFO("imx_hdcp_secure_open_context\n");
	if (busId < PTA_HDCP_HDP_BUSID || busId >= PTA_HDCP_MAX_BUSID)
	{
		pr_err("%s busId %d is not supported\n",__func__, busId);
		return false;
	}
	ctx = tee_client_open_context(NULL, imx_hdcp_optee_match, NULL, &vers);
	if (IS_ERR(ctx))
	{
		pr_err("unable to open tee ctx %p\n",(void*)ctx);
		return false;
	}

	imx_hdcp_secure_set_context(busId,ctx);

	return true;
}

void imx_hdcp_secure_close_context(uint32_t busId)
{
	struct tee_context *ctx;

	if (busId < PTA_HDCP_HDP_BUSID || busId >= PTA_HDCP_MAX_BUSID)
	{
		pr_err("%s busId %d is not supported\n",__func__, busId);
		return;
	}
	ctx = imx_hdcp_secure_get_context(busId);
	if (ctx)
	{
		tee_client_close_context(ctx);
		imx_hdcp_secure_set_context(busId,NULL);
	}
}

bool imx_hdcp_secure_open_session(uint32_t busId)
{
	const RTC_UUID pta_uuid = HDCP_PTA_UUID;
	struct tee_ioctl_open_session_arg sess_arg;
	struct tee_param param[4];
	struct tee_param *params = NULL;
	int result;
	struct tee_context *ctx;

	DRM_INFO("imx_hdcp_secure_open_session\n");

	if (busId < PTA_HDCP_HDP_BUSID || busId >= PTA_HDCP_MAX_BUSID)
	{
		pr_err("%s busId %d is not supported\n",__func__, busId);
		return false;
	}
	ctx = imx_hdcp_secure_get_context(busId);
	if (ctx == NULL)
	{
		pr_err("%s can't get tee_context for busId %d\n",__func__, busId);
		return false;
	}
	memset(&sess_arg, 0, sizeof(sess_arg));
	memset(&param, 0, sizeof(param));

	/* Open session with pseudo HDCP TA */
	uuid_to_octets(sess_arg.uuid, &pta_uuid);
	sess_arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;
	sess_arg.num_params = 4;

	/* Fill invoke cmd params */
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[0].u.value.a = busId;
	params = param;
	result = tee_client_open_session(ctx, &sess_arg, params);
	if ((result < 0) || sess_arg.ret)
	{
		return false;
	}
	imx_hdcp_secure_set_session(busId, sess_arg.session);
	return true;
}

void imx_hdp_secure_close_session(uint32_t busId)
{
	struct tee_context *ctx;
	uint32_t session;

	DRM_INFO("imx_hdp_secure_close_session\n");

	if (busId < PTA_HDCP_HDP_BUSID || busId >= PTA_HDCP_MAX_BUSID)
	{
		pr_err("%s busId %d is not supported\n",__func__, busId);
		return;
	}
	ctx = imx_hdcp_secure_get_context(busId);
	if (ctx)
	{
		session = imx_hdcp_secure_get_session(busId);
		tee_client_close_session(ctx,session);
		imx_hdcp_secure_set_session(busId,0);
	}
}

