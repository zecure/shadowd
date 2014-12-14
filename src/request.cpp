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

#include "request.h"

void swd::request::set_profile(swd::profile_ptr profile) {
	profile_ = profile;
}

swd::profile_ptr swd::request::get_profile() {
	return profile_;
}

void swd::request::add_parameter(std::string key, std::string value) {
	swd::parameter_ptr parameter(new swd::parameter(value));
	parameters_[key] = parameter;
}

swd::parameters& swd::request::get_parameters() {
	return parameters_;
}

void swd::request::append_content(char input) {
	content_.push_back(input);
}

std::string swd::request::get_content() {
	return content_;
}

void swd::request::append_signature(char input) {
	signature_.push_back(input);
}

std::string swd::request::get_signature() {
	return signature_;
}

void swd::request::append_profile_id(char input) {
	profile_id_.push_back(input);
}

int swd::request::get_profile_id() {
	return atoi(profile_id_.c_str());
}

void swd::request::set_client_ip(std::string client_ip) {
	client_ip_ = client_ip;
}

std::string swd::request::get_client_ip() {
	return client_ip_;
}

void swd::request::set_caller(std::string caller) {
	caller_ = caller;
}

std::string swd::request::get_caller() {
	return caller_;
}

bool swd::request::has_threats() {
	/* Iterate over all parameters and check for threats. */
	for (swd::parameters::iterator it_parameter = parameters_.begin();
	 it_parameter != parameters_.end(); it_parameter++) {
		swd::parameter_ptr parameter((*it_parameter).second);

		/* We only need to know if there is at least one threat. */
		if (parameter->is_threat()) {
			return true;
		}
	}

	return false;
}
