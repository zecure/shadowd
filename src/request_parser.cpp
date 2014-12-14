/**
 * Shadow Daemon -- Web Application Firewall
 *
 *   Copyright (C) 2014 Hendrik Buchwald <hb@zecure.org>
 *
 * This file is part of Shadow Daemon. Shadow Daemon is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cctype>

#include "request_parser.h"

swd::request_parser::request_parser() :
 state_(profile) {
}

boost::tribool swd::request_parser::consume(swd::request_ptr request, char input) {
	switch (state_) {
		case profile:
			if (input == '\n') {
				state_ = signature;
				return boost::indeterminate;
			} else if (isdigit(input)) {
				request->append_profile_id(input);
				return boost::indeterminate;
			} else {
				return false;
			}
		case signature:
			if (input == '\n') {
				state_ = content;
				return boost::indeterminate;
			} else if (isalnum(input)) {
				request->append_signature(input);
				return boost::indeterminate;
			} else {
				return false;
			}
		case content:
			if (input == '\n') {
				return true;
			} else {
				request->append_content(input);
				return boost::indeterminate;
			}
		default:
			return false;
	}
}
