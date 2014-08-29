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

#include <string>
#include <vector>
#include <jsoncpp/json/json.h>

#include "reply_handler.h"
#include "log.h"

swd::reply_handler::reply_handler(swd::reply_ptr reply) :
 reply_(reply) {
}

bool swd::reply_handler::encode() {
	try {
		Json::Value root;
		Json::FastWriter writer;

		root["status"] = reply_->get_status();
		std::vector<std::string> threats = reply_->get_threats();

		Json::Value output(Json::arrayValue);
		for (std::vector<std::string>::iterator it = threats.begin(); it != threats.end(); ++it) {
			output.append(*it);
		}

		root["threats"] = output;

		reply_->set_content(writer.write(root));

	} catch (...) {
		swd::log::i()->send(swd::uncritical_error, "Uncaught json encode exception");
		return false;
	}

	return true;
}
