// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2025 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include "core.h"
#include "acpi.h"
#include "debug.h"

static int ath12k_acpi_dsm_get_data(struct ath12k_base *ab, int func)
{
	union acpi_object *obj;
	acpi_handle root_handle;
	int ret, i;

	root_handle = ACPI_HANDLE(ab->dev);
	if (!root_handle) {
		ath12k_dbg(ab, ATH12K_DBG_BOOT, "invalid acpi handler\n");
		return -EOPNOTSUPP;
	}

	obj = acpi_evaluate_dsm(root_handle, ab->hw_params->acpi_guid, 0, func,
				NULL);

	if (!obj) {
		ath12k_dbg(ab, ATH12K_DBG_BOOT, "acpi_evaluate_dsm() failed\n");
		return -ENOENT;
	}

	if (obj->type == ACPI_TYPE_INTEGER) {
		switch (func) {
		case ATH12K_ACPI_DSM_FUNC_SUPPORT_FUNCS:
			ab->acpi.func_bit = obj->integer.value;
			break;
		case ATH12K_ACPI_DSM_FUNC_DISABLE_FLAG:
			ab->acpi.bit_flag = obj->integer.value;
			break;
		}
	} else if (obj->type == ACPI_TYPE_STRING) {
		switch (func) {
		case ATH12K_ACPI_DSM_FUNC_BDF_EXT:
			if (obj->string.length <= ATH12K_ACPI_BDF_ANCHOR_STRING_LEN ||
			    obj->string.length > ATH12K_ACPI_BDF_MAX_LEN ||
			    memcmp(obj->string.pointer, ATH12K_ACPI_BDF_ANCHOR_STRING,
				   ATH12K_ACPI_BDF_ANCHOR_STRING_LEN)) {
				ath12k_warn(ab, "invalid ACPI DSM BDF size: %d\n",
					    obj->string.length);
				ret = -EINVAL;
				goto out;
			}

			memcpy(ab->acpi.bdf_string, obj->string.pointer,
			       obj->buffer.length);

			break;
		}
	} else if (obj->type == ACPI_TYPE_BUFFER) {
		switch (func) {
		case ATH12K_ACPI_DSM_FUNC_SUPPORT_FUNCS:
			if (obj->buffer.length < ATH12K_ACPI_DSM_FUNC_MIN_BITMAP_SIZE ||
			    obj->buffer.length > ATH12K_ACPI_DSM_FUNC_MAX_BITMAP_SIZE) {
				ath12k_warn(ab, "invalid ACPI DSM func size: %d\n",
					    obj->buffer.length);
				ret = -EINVAL;
				goto out;
			}

			ab->acpi.func_bit = 0;
			for (i = 0; i < obj->buffer.length; i++)
				ab->acpi.func_bit += obj->buffer.pointer[i] << (i * 8);

			break;
		case ATH12K_ACPI_DSM_FUNC_TAS_CFG:
			if (obj->buffer.length != ATH12K_ACPI_DSM_TAS_CFG_SIZE) {
				ath12k_warn(ab, "invalid ACPI DSM TAS config size: %d\n",
					    obj->buffer.length);
				ret = -EINVAL;
				goto out;
			}

			memcpy(&ab->acpi.tas_cfg, obj->buffer.pointer,
			       obj->buffer.length);

			break;
		case ATH12K_ACPI_DSM_FUNC_TAS_DATA:
			if (obj->buffer.length != ATH12K_ACPI_DSM_TAS_DATA_SIZE) {
				ath12k_warn(ab, "invalid ACPI DSM TAS data size: %d\n",
					    obj->buffer.length);
				ret = -EINVAL;
				goto out;
			}

			memcpy(&ab->acpi.tas_sar_power_table, obj->buffer.pointer,
			       obj->buffer.length);

			break;
		case ATH12K_ACPI_DSM_FUNC_BIOS_SAR:
			if (obj->buffer.length != ATH12K_ACPI_DSM_BIOS_SAR_DATA_SIZE) {
				ath12k_warn(ab, "invalid ACPI BIOS SAR data size: %d\n",
					    obj->buffer.length);
				ret = -EINVAL;
				goto out;
			}

			memcpy(&ab->acpi.bios_sar_data, obj->buffer.pointer,
			       obj->buffer.length);

			break;
		case ATH12K_ACPI_DSM_FUNC_GEO_OFFSET:
			if (obj->buffer.length != ATH12K_ACPI_DSM_GEO_OFFSET_DATA_SIZE) {
				ath12k_warn(ab, "invalid ACPI GEO OFFSET data size: %d\n",
					    obj->buffer.length);
				ret = -EINVAL;
				goto out;
			}

			memcpy(&ab->acpi.geo_offset_data, obj->buffer.pointer,
			       obj->buffer.length);

			break;
		case ATH12K_ACPI_DSM_FUNC_INDEX_CCA:
			if (obj->buffer.length != ATH12K_ACPI_DSM_CCA_DATA_SIZE) {
				ath12k_warn(ab, "invalid ACPI DSM CCA data size: %d\n",
					    obj->buffer.length);
				ret = -EINVAL;
				goto out;
			}

			memcpy(&ab->acpi.cca_data, obj->buffer.pointer,
			       obj->buffer.length);

			break;
		case ATH12K_ACPI_DSM_FUNC_INDEX_BAND_EDGE:
			if (obj->buffer.length != ATH12K_ACPI_DSM_BAND_EDGE_DATA_SIZE) {
				ath12k_warn(ab, "invalid ACPI DSM band edge data size: %d\n",
					    obj->buffer.length);
				ret = -EINVAL;
				goto out;
			}

			memcpy(&ab->acpi.band_edge_power, obj->buffer.pointer,
			       obj->buffer.length);

			break;
		}
	} else {
		ath12k_warn(ab, "ACPI DSM method returned an unsupported object type: %d\n",
			    obj->type);
		ret = -EINVAL;
		goto out;
	}

	ret = 0;

out:
	ACPI_FREE(obj);
	return ret;
}

static int ath12k_acpi_set_power_limit(struct ath12k_base *ab)
{
	const u8 *tas_sar_power_table = ab->acpi.tas_sar_power_table;
	int ret;

	if (tas_sar_power_table[0] != ATH12K_ACPI_TAS_DATA_VERSION ||
	    tas_sar_power_table[1] != ATH12K_ACPI_TAS_DATA_ENABLE) {
		ath12k_warn(ab, "latest ACPI TAS data is invalid\n");
		return -EINVAL;
	}

	ret = ath12k_wmi_set_bios_cmd(ab, WMI_BIOS_PARAM_TAS_DATA_TYPE,
				      tas_sar_power_table,
				      ATH12K_ACPI_DSM_TAS_DATA_SIZE);
	if (ret) {
		ath12k_warn(ab, "failed to send ACPI TAS data table: %d\n", ret);
		return ret;
	}

	return ret;
}

static int ath12k_acpi_set_bios_sar_power(struct ath12k_base *ab)
{
	int ret;

	if (ab->acpi.bios_sar_data[0] != ATH12K_ACPI_POWER_LIMIT_VERSION ||
	    ab->acpi.bios_sar_data[1] != ATH12K_ACPI_POWER_LIMIT_ENABLE_FLAG) {
		ath12k_warn(ab, "invalid latest ACPI BIOS SAR data\n");
		return -EINVAL;
	}

	ret = ath12k_wmi_set_bios_sar_cmd(ab, ab->acpi.bios_sar_data);
	if (ret) {
		ath12k_warn(ab, "failed to set ACPI BIOS SAR table: %d\n", ret);
		return ret;
	}

	return 0;
}

static void ath12k_acpi_dsm_notify(acpi_handle handle, u32 event, void *data)
{
	int ret;
	struct ath12k_base *ab = data;

	if (event == ATH12K_ACPI_NOTIFY_EVENT) {
		ath12k_warn(ab, "unknown acpi notify %u\n", event);
		return;
	}

	if (!ab->acpi.acpi_tas_enable) {
		ath12k_dbg(ab, ATH12K_DBG_BOOT, "acpi_tas_enable is false\n");
		return;
	}

	ret = ath12k_acpi_dsm_get_data(ab, ATH12K_ACPI_DSM_FUNC_TAS_DATA);
	if (ret) {
		ath12k_warn(ab, "failed to update ACPI TAS data table: %d\n", ret);
		return;
	}

	ret = ath12k_acpi_set_power_limit(ab);
	if (ret) {
		ath12k_warn(ab, "failed to set ACPI TAS power limit data: %d", ret);
		return;
	}

	if (!ab->acpi.acpi_bios_sar_enable)
		return;

	ret = ath12k_acpi_dsm_get_data(ab, ATH12K_ACPI_DSM_FUNC_BIOS_SAR);
	if (ret) {
		ath12k_warn(ab, "failed to update BIOS SAR: %d\n", ret);
		return;
	}

	ret = ath12k_acpi_set_bios_sar_power(ab);
	if (ret) {
		ath12k_warn(ab, "failed to set BIOS SAR power limit: %d\n", ret);
		return;
	}
}

static int ath12k_acpi_set_bios_sar_params(struct ath12k_base *ab)
{
	int ret;

	ret = ath12k_wmi_set_bios_sar_cmd(ab, ab->acpi.bios_sar_data);
	if (ret) {
		ath12k_warn(ab, "failed to set ACPI BIOS SAR table: %d\n", ret);
		return ret;
	}

	ret = ath12k_wmi_set_bios_geo_cmd(ab, ab->acpi.geo_offset_data);
	if (ret) {
		ath12k_warn(ab, "failed to set ACPI BIOS GEO table: %d\n", ret);
		return ret;
	}

	return 0;
}

static int ath12k_acpi_set_tas_params(struct ath12k_base *ab)
{
	int ret;

	ret = ath12k_wmi_set_bios_cmd(ab, WMI_BIOS_PARAM_TAS_CONFIG_TYPE,
				      ab->acpi.tas_cfg,
				      ATH12K_ACPI_DSM_TAS_CFG_SIZE);
	if (ret) {
		ath12k_warn(ab, "failed to send ACPI TAS config table parameter: %d\n",
			    ret);
		return ret;
	}

	ret = ath12k_wmi_set_bios_cmd(ab, WMI_BIOS_PARAM_TAS_DATA_TYPE,
				      ab->acpi.tas_sar_power_table,
				      ATH12K_ACPI_DSM_TAS_DATA_SIZE);
	if (ret) {
		ath12k_warn(ab, "failed to send ACPI TAS data table parameter: %d\n",
			    ret);
		return ret;
	}

	return 0;
}

bool ath12k_acpi_get_disable_rfkill(struct ath12k_base *ab)
{
	return ab->acpi.acpi_disable_rfkill;
}

bool ath12k_acpi_get_disable_11be(struct ath12k_base *ab)
{
	return ab->acpi.acpi_disable_11be;
}

void ath12k_acpi_set_dsm_func(struct ath12k_base *ab)
{
	int ret;
	u8 *buf;

	if (!ab->hw_params->acpi_guid)
		/* not supported with this hardware */
		return;

	if (ab->acpi.acpi_tas_enable) {
		ret = ath12k_acpi_set_tas_params(ab);
		if (ret) {
			ath12k_warn(ab, "failed to send ACPI TAS parameters: %d\n", ret);
			return;
		}
	}

	if (ab->acpi.acpi_bios_sar_enable) {
		ret = ath12k_acpi_set_bios_sar_params(ab);
		if (ret) {
			ath12k_warn(ab, "failed to send ACPI BIOS SAR: %d\n", ret);
			return;
		}
	}

	if (ab->acpi.acpi_cca_enable) {
		buf = ab->acpi.cca_data + ATH12K_ACPI_CCA_THR_OFFSET_DATA_OFFSET;
		ret = ath12k_wmi_set_bios_cmd(ab,
					      WMI_BIOS_PARAM_CCA_THRESHOLD_TYPE,
					      buf,
					      ATH12K_ACPI_CCA_THR_OFFSET_LEN);
		if (ret) {
			ath12k_warn(ab, "failed to set ACPI DSM CCA threshold: %d\n",
				    ret);
			return;
		}
	}

	if (ab->acpi.acpi_band_edge_enable) {
		ret = ath12k_wmi_set_bios_cmd(ab,
					      WMI_BIOS_PARAM_TYPE_BANDEDGE,
					      ab->acpi.band_edge_power,
					      sizeof(ab->acpi.band_edge_power));
		if (ret) {
			ath12k_warn(ab,
				    "failed to set ACPI DSM band edge channel power: %d\n",
				    ret);
			return;
		}
	}
}

int ath12k_acpi_start(struct ath12k_base *ab)
{
	acpi_status status;
	int ret;

	ab->acpi.acpi_tas_enable = false;
	ab->acpi.acpi_disable_11be = false;
	ab->acpi.acpi_disable_rfkill = false;
	ab->acpi.acpi_bios_sar_enable = false;
	ab->acpi.acpi_cca_enable = false;
	ab->acpi.acpi_band_edge_enable = false;
	ab->acpi.acpi_enable_bdf = false;
	ab->acpi.bdf_string[0] = '\0';

	if (!ab->hw_params->acpi_guid)
		/* not supported with this hardware */
		return 0;

	ret = ath12k_acpi_dsm_get_data(ab, ATH12K_ACPI_DSM_FUNC_SUPPORT_FUNCS);
	if (ret) {
		ath12k_dbg(ab, ATH12K_DBG_BOOT, "failed to get ACPI DSM data: %d\n", ret);
		return ret;
	}

	if (ATH12K_ACPI_FUNC_BIT_VALID(ab->acpi, ATH12K_ACPI_FUNC_BIT_DISABLE_FLAG)) {
		ret = ath12k_acpi_dsm_get_data(ab, ATH12K_ACPI_DSM_FUNC_DISABLE_FLAG);
		if (ret) {
			ath12k_warn(ab, "failed to get ACPI DISABLE FLAG: %d\n", ret);
			return ret;
		}

		if (ATH12K_ACPI_CHEK_BIT_VALID(ab->acpi,
					       ATH12K_ACPI_DSM_DISABLE_11BE_BIT))
			ab->acpi.acpi_disable_11be = true;

		if (!ATH12K_ACPI_CHEK_BIT_VALID(ab->acpi,
						ATH12K_ACPI_DSM_DISABLE_RFKILL_BIT))
			ab->acpi.acpi_disable_rfkill = true;
	}

	if (ATH12K_ACPI_FUNC_BIT_VALID(ab->acpi, ATH12K_ACPI_FUNC_BIT_BDF_EXT)) {
		ret = ath12k_acpi_dsm_get_data(ab, ATH12K_ACPI_DSM_FUNC_BDF_EXT);
		if (ret || ab->acpi.bdf_string[0] == '\0') {
			ath12k_warn(ab, "failed to get ACPI BDF EXT: %d\n", ret);
			return ret;
		}

		ab->acpi.acpi_enable_bdf = true;
	}

	if (ATH12K_ACPI_FUNC_BIT_VALID(ab->acpi, ATH12K_ACPI_FUNC_BIT_TAS_CFG)) {
		ret = ath12k_acpi_dsm_get_data(ab, ATH12K_ACPI_DSM_FUNC_TAS_CFG);
		if (ret) {
			ath12k_warn(ab, "failed to get ACPI TAS config table: %d\n", ret);
			return ret;
		}
	}

	if (ATH12K_ACPI_FUNC_BIT_VALID(ab->acpi, ATH12K_ACPI_FUNC_BIT_TAS_DATA)) {
		ret = ath12k_acpi_dsm_get_data(ab, ATH12K_ACPI_DSM_FUNC_TAS_DATA);
		if (ret) {
			ath12k_warn(ab, "failed to get ACPI TAS data table: %d\n", ret);
			return ret;
		}

		if (ATH12K_ACPI_FUNC_BIT_VALID(ab->acpi, ATH12K_ACPI_FUNC_BIT_TAS_CFG) &&
		    ab->acpi.tas_sar_power_table[0] == ATH12K_ACPI_TAS_DATA_VERSION &&
		    ab->acpi.tas_sar_power_table[1] == ATH12K_ACPI_TAS_DATA_ENABLE)
			ab->acpi.acpi_tas_enable = true;
	}

	if (ATH12K_ACPI_FUNC_BIT_VALID(ab->acpi, ATH12K_ACPI_FUNC_BIT_BIOS_SAR)) {
		ret = ath12k_acpi_dsm_get_data(ab, ATH12K_ACPI_DSM_FUNC_BIOS_SAR);
		if (ret) {
			ath12k_warn(ab, "failed to get ACPI bios sar data: %d\n", ret);
			return ret;
		}
	}

	if (ATH12K_ACPI_FUNC_BIT_VALID(ab->acpi, ATH12K_ACPI_FUNC_BIT_GEO_OFFSET)) {
		ret = ath12k_acpi_dsm_get_data(ab, ATH12K_ACPI_DSM_FUNC_GEO_OFFSET);
		if (ret) {
			ath12k_warn(ab, "failed to get ACPI geo offset data: %d\n", ret);
			return ret;
		}

		if (ATH12K_ACPI_FUNC_BIT_VALID(ab->acpi, ATH12K_ACPI_FUNC_BIT_BIOS_SAR) &&
		    ab->acpi.bios_sar_data[0] == ATH12K_ACPI_POWER_LIMIT_VERSION &&
		    ab->acpi.bios_sar_data[1] == ATH12K_ACPI_POWER_LIMIT_ENABLE_FLAG &&
		    !ab->acpi.acpi_tas_enable)
			ab->acpi.acpi_bios_sar_enable = true;
	}

	if (ATH12K_ACPI_FUNC_BIT_VALID(ab->acpi, ATH12K_ACPI_FUNC_BIT_CCA)) {
		ret = ath12k_acpi_dsm_get_data(ab, ATH12K_ACPI_DSM_FUNC_INDEX_CCA);
		if (ret) {
			ath12k_warn(ab, "failed to get ACPI DSM CCA threshold configuration: %d\n",
				    ret);
			return ret;
		}

		if (ab->acpi.cca_data[0] == ATH12K_ACPI_CCA_THR_VERSION &&
		    ab->acpi.cca_data[ATH12K_ACPI_CCA_THR_OFFSET_DATA_OFFSET] ==
		    ATH12K_ACPI_CCA_THR_ENABLE_FLAG)
			ab->acpi.acpi_cca_enable = true;
	}

	if (ATH12K_ACPI_FUNC_BIT_VALID(ab->acpi,
				       ATH12K_ACPI_FUNC_BIT_BAND_EDGE_CHAN_POWER)) {
		ret = ath12k_acpi_dsm_get_data(ab, ATH12K_ACPI_DSM_FUNC_INDEX_BAND_EDGE);
		if (ret) {
			ath12k_warn(ab, "failed to get ACPI DSM band edge channel power: %d\n",
				    ret);
			return ret;
		}

		if (ab->acpi.band_edge_power[0] == ATH12K_ACPI_BAND_EDGE_VERSION &&
		    ab->acpi.band_edge_power[1] == ATH12K_ACPI_BAND_EDGE_ENABLE_FLAG)
			ab->acpi.acpi_band_edge_enable = true;
	}

	status = acpi_install_notify_handler(ACPI_HANDLE(ab->dev),
					     ACPI_DEVICE_NOTIFY,
					     ath12k_acpi_dsm_notify, ab);
	if (ACPI_FAILURE(status)) {
		ath12k_warn(ab, "failed to install DSM notify callback: %d\n", status);
		return -EIO;
	}

	ab->acpi.started = true;

	return 0;
}

int ath12k_acpi_check_bdf_variant_name(struct ath12k_base *ab)
{
	size_t max_len = sizeof(ab->qmi.target.bdf_ext);

	if (!ab->acpi.acpi_enable_bdf)
		return -ENODATA;

	if (strscpy(ab->qmi.target.bdf_ext, ab->acpi.bdf_string + 4, max_len) < 0)
		ath12k_dbg(ab, ATH12K_DBG_BOOT,
			   "acpi bdf variant longer than the buffer (variant: %s)\n",
			   ab->acpi.bdf_string);

	return 0;
}

void ath12k_acpi_stop(struct ath12k_base *ab)
{
	if (!ab->acpi.started)
		return;

	acpi_remove_notify_handler(ACPI_HANDLE(ab->dev),
				   ACPI_DEVICE_NOTIFY,
				   ath12k_acpi_dsm_notify);

	memset(&ab->acpi, 0, sizeof(ab->acpi));
}
