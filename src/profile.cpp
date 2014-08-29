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

#include "profile.h"

swd::profile::profile(std::string server_ip, int id, bool learning,
 std::string key, int threshold) :
 server_ip_(server_ip),
 id_(id),
 learning_(learning),
 key_ (key),
 threshold_ (threshold) {
}

int swd::profile::get_id() {
	return id_;
}

bool swd::profile::is_learning() {
	return learning_;
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
