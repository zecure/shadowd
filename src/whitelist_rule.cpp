/**
 * Shadow Daemon -- Web Application Firewall
 *
 *   Copyright (C) 2014-2015 Hendrik Buchwald <hb@zecure.org>
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

#include "whitelist_rule.h"

swd::whitelist_rule::whitelist_rule(int id, swd::whitelist_filter_ptr filter,
 int min_length, int max_length) :
 id_(id),
 filter_(filter),
 min_length_(min_length),
 max_length_(max_length) {
}

int swd::whitelist_rule::get_id() {
	return id_;
}

bool swd::whitelist_rule::is_adhered_to(std::string value) {
	int length = value.length();

	if ((min_length_ > 0) && (length < min_length_)) {
		return false;
	}

	if ((max_length_ > 0) && (length > max_length_)) {
		return false;
	}

	return filter_->match(value);
}
