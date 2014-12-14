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

#include <string>
#include <boost/lexical_cast.hpp>

#include "reply.h"

std::vector<boost::asio::const_buffer> swd::reply::to_buffers() {
	std::vector<boost::asio::const_buffer> buffers;
	buffers.push_back(boost::asio::buffer(content_));
	return buffers;
}

void swd::reply::set_status(int status) {
	status_ = status;
}

int swd::reply::get_status() {
	return status_;
}

void swd::reply::set_threats(std::vector<std::string> threats) {
	threats_ = threats;
}

std::vector<std::string> swd::reply::get_threats() {
	return threats_;
}

void swd::reply::set_content(std::string content) {
	content_ = content;
}
