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

#include "blacklist_filter.h"

swd::blacklist_filter::blacklist_filter(int id, std::string rule, int impact) :
 id_(id),
 impact_(impact) {
	rule_.set_expression(rule, boost::regex::icase | boost::regex::mod_s);
}

int swd::blacklist_filter::get_id() {
	return id_;
}

int swd::blacklist_filter::get_impact() {
	return impact_;
}

bool swd::blacklist_filter::match(std::string input) {
	return regex_search(input, rule_);
}
