/***************************************************************************
 *   Copyright (C) 2018 Dean Miller                                        *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include "helper/binarybuffer.h"

#include <target/bfinplus.h>

#define EZ_FLASH			((uint32_t)0x00000000)

#define EZ_LOAD_BASE_ADDR       (0x11900000ul)

//the command register
#define EZ_LOAD_CMD_OFFSET      (0x00ul)
#define EZ_LOAD_CMD             (EZ_LOAD_BASE_ADDR + EZ_LOAD_CMD_OFFSET)

//the address register
#define EZ_LOAD_ADDR_OFFSET     (0x04ul)
#define EZ_LOAD_ADDR            (EZ_LOAD_BASE_ADDR + EZ_LOAD_ADDR_OFFSET)

//the count register
#define EZ_LOAD_COUNT_OFFSET    (0x08ul)
#define EZ_LOAD_COUNT           (EZ_LOAD_BASE_ADDR + EZ_LOAD_COUNT_OFFSET)

//the status register
#define EZ_LOAD_STATUS_OFFSET   (0x0Cul)
#define EZ_LOAD_STATUS          (EZ_LOAD_BASE_ADDR + EZ_LOAD_STATUS_OFFSET)

//the page buffer
#define EZ_LOAD_PAGE_OFFSET     (0x10ul)
#define EZ_LOAD_PAGE            (EZ_LOAD_BASE_ADDR + EZ_LOAD_PAGE_OFFSET)

//the high byte must be set to this to execute
#define EZ_CMD_EXECUTE          (0xA5ul)

#define EZ_CMD_CHIP_ERASE       (0x01ul)
#define EZ_CMD_ERASE_BLOCK      (0x02ul)
#define EZ_CMD_WRITE_BLOCK      (0x03ul)
#define EZ_CMD_READ_BLOCK       (0x04ul)
#define EZ_CMD_INFO             (0x05ul)

#define EZ_STATUS_OK            (0x00ul)
#define EZ_STATUS_BUSY          (0x01ul)
#define EZ_STATUS_ERROR         (0x02ul)

#define EZ_CMD(x) ( (EZ_CMD_EXECUTE << 8) | (x) )

struct ez_info {
	uint32_t page_size;
	int num_pages;
	int sector_size;
	int prot_block_size;

	bool probed;
	struct target *target;
	struct ez_info *next;
};

static struct ez_info *ez_chips;

static int halt_target(struct target *target)
{
	int res;
	if (target->state != TARGET_HALTED) {
		res = target_halt(target);
		if (res != ERROR_OK)
			return res;

		//wait for the target to be halted
		while(target->state != TARGET_HALTED){
			usleep(10);
			res = target_poll(target);
			if (res != ERROR_OK)
				return res;
		}
	}
	return ERROR_OK;
}

static int ez_check_status(struct target *target, uint16_t *status)
{
	int res;

	res = halt_target(target);
	if (res != ERROR_OK)
		return res;

	res = target_read_u16(target, EZ_LOAD_STATUS, status);
	if (res != ERROR_OK)
		return res;

	/* Resume target so it can execute command */
	return target_resume(target, 1, 0, 0, 0);
}

static int ez_issue_command(struct target *target, uint16_t cmd)
{
	int res;
	uint16_t err;
	res = halt_target(target);
	if (res != ERROR_OK)
		return res;

	LOG_DEBUG("issue cmd: 0x%" PRIx32, (uint32_t)cmd);

	/* Issue the NVM command */
	res = target_write_u16(target, EZ_LOAD_CMD, EZ_CMD(cmd));
	if (res != ERROR_OK)
		return res;

	/* Resume target so it can execute command */
	res = target_resume(target, 1, 0, 0, 0);
	if (res != ERROR_OK)
		return res;

	res = ez_check_status(target, &err);
	if (res != ERROR_OK)
		return res;
	else if (err == EZ_STATUS_ERROR)
		return ERROR_FAIL;
	else return ERROR_OK;
}

static int ez_probe(struct flash_bank *bank){

	LOG_DEBUG("probing");

	ez_issue_command(bank->target, EZ_CMD_INFO);

	return ERROR_OK;
}

static int ez_erase_row(struct target *target, uint32_t address)
{
	LOG_DEBUG("erase row at: 0x%" PRIx32, address);
	return ERROR_OK;
}

static int ez_protect(struct flash_bank *bank, int set, int first_prot_bl, int last_prot_bl)
{
	LOG_DEBUG("protect command received. Not doing anything.");
	return ERROR_OK;
}

static int ez_protect_check(struct flash_bank *bank)
{
	LOG_DEBUG("protect check command received. Not doing anything.");
	return ERROR_OK;
}

static int ez_erase(struct flash_bank *bank, int first_sect, int last_sect)
{
	struct ez_info *chip = ez_chips;

	if (!chip->probed) {
		if (ez_probe(bank) != ERROR_OK)
			return ERROR_FLASH_BANK_NOT_PROBED;
	}
	LOG_DEBUG("erase at: 0x%" PRIx32, (uint32_t)first_sect);
	LOG_DEBUG("end erase at: 0x%" PRIx32, (uint32_t)last_sect);

	return ERROR_OK;
}


static int ez_write(struct flash_bank *bank, const uint8_t *buffer,
		uint32_t offset, uint32_t count)
{
	struct ez_info *chip = ez_chips;

	if (!chip->probed) {
		if (ez_probe(bank) != ERROR_OK)
			return ERROR_FLASH_BANK_NOT_PROBED;
	}

	LOG_DEBUG("write bytes at: 0x%" PRIx32, (uint32_t)offset);

	return ERROR_OK;
}

FLASH_BANK_COMMAND_HANDLER(ez_flash_bank_command)
{
	struct ez_info *chip = ez_chips;

	while (chip) {
		if (chip->target == bank->target)
			break;
		chip = chip->next;
	}

	if (!chip) {
		/* Create a new chip */
		chip = calloc(1, sizeof(*chip));
		if (!chip)
			return ERROR_FAIL;

		chip->target = bank->target;
		chip->probed = false;

		bank->driver_priv = chip;

		/* Insert it into the chips list (at head) */
		chip->next = ez_chips;
		ez_chips = chip;
	}

	if (bank->base != EZ_FLASH) {
		LOG_ERROR("Address 0x%08" PRIx32 " invalid bank address (try 0x%08" PRIx32
				"[bf70xEzKit series] )",
				bank->base, EZ_FLASH);
		return ERROR_FAIL;
	}

	return ERROR_OK;
}

COMMAND_HANDLER(ez_handle_info_command)
{
	return ERROR_OK;
}

COMMAND_HANDLER(ez_handle_chip_erase_command)
{
	struct target *target = get_current_target(CMD_CTX);
	int res = ERROR_FAIL;

	if (target) {
		//TODO: write chip erase command

		if (res == ERROR_OK)
			command_print(CMD_CTX, "chip erase started");
	}

	return res;
}

static const struct command_registration bf70xEzKit_exec_command_handlers[] = {
	{
		.name = "info",
		.handler = ez_handle_info_command,
		.mode = COMMAND_EXEC,
		.help = "Print information about the current bf70x ez-kit board flash chip"
			"and its flash configuration.",
	},
	{
		.name = "chip-erase",
		.handler = ez_handle_chip_erase_command,
		.mode = COMMAND_EXEC,
		.help = "Erase the entire Flash by using the Chip Erase command",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration bf70xEzKit_command_handlers[] = {
	{
		.name = "bf70xEzKit",
		.mode = COMMAND_ANY,
		.help = "bf70x ez-kit flash command group",
		.usage = "",
		.chain = bf70xEzKit_exec_command_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

struct flash_driver bf70x_ez_kit_flash = {
	.name = "bf70x-ez-kit",
	.commands = bf70xEzKit_command_handlers,
	.flash_bank_command = ez_flash_bank_command,
	.erase = ez_erase,
	.protect = ez_protect,
	.write = ez_write,
	.read = default_flash_read,
	.probe = ez_probe,
	.auto_probe = ez_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = ez_protect_check,
};
