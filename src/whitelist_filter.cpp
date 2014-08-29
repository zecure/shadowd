/**
 * Shadow Daemon -- High-Interaction Web Honeypot
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

#include "whitelist_filter.h"

swd::whitelist_filter::whitelist_filter(int id, std::string rule) :
 id_(id) {
	rule_.set_expression(rule, boost::regex::icase | boost::regex::mod_s);
}

int swd::whitelist_filter::get_id() {
	return id_;
}

bool swd::whitelist_filter::match(std::string input) {
	return regex_search(input, rule_);
}
