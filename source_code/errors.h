/*
 * :ts=4
 *
 * SMB file system wrapper for AmigaOS, using the AmiTCP V3 API
 *
 * Copyright (C) 2000-2018 by Olaf `Olsen' Barthel <obarthel -at- gmx -dot- net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

enum
{
	error_end_of_file=10000,
	error_invalid_netbios_session,
	error_message_exceeds_buffer_size,
	error_invalid_buffer_format,
	error_data_exceeds_buffer_size,
	error_invalid_parameter_size,
	error_check_smb_error,
	error_server_setup_incomplete,
	error_server_connection_invalid,
	error_smb_message_signature_missing,
	error_smb_message_too_short,
	error_smb_message_invalid_command,
	error_smb_message_invalid_word_count,
	error_smb_message_invalid_byte_count,
	error_looping_in_find_next,
	error_invalid_directory_size,
	error_session_request_failed,
	error_unsupported_dialect,
};
