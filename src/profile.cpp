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

#include "profile.h"

swd::profile::profile(std::string server_ip, int id, bool learning_enabled,
 bool whitelist_enabled, bool blacklist_enabled, std::string key, int threshold) :
 server_ip_(server_ip),
 id_(id),
 learning_enabled_(learning_enabled),
 whitelist_enabled_(whitelist_enabled),
 blacklist_enabled_(blacklist_enabled),
 key_(key),
 threshold_(threshold) {
}

int swd::profile::get_id() {
	return id_;
}

bool swd::profile::is_learning_enabled() {
	return learning_enabled_;
}

bool swd::profile::is_whitelist_enabled() {
	return whitelist_enabled_;
}

bool swd::profile::is_blacklist_enabled() {
	return blacklist_enabled_;
}

std::string swd::profile::get_key() {
	return key_;
}

int swd::profile::get_threshold() {
	return threshold_;
}

std::string swd::profile::get_server_ip() {
	return server_ip_;
}
