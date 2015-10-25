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
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <jsoncpp/json/json.h>

#include "request_handler.h"
#include "analyzer.h"
#include "storage.h"
#include "log.h"

swd::request_handler::request_handler(swd::request_ptr request) :
 request_(request) {
}

bool swd::request_handler::valid_signature() {
	try {
		std::string key = request_->get_profile()->get_key();
		std::string mac, hex_mac;

		CryptoPP::HMAC<CryptoPP::SHA256> hmac(
			(const byte *)key.c_str(),
			key.size()
		);

		/* Generate mac (hash) from hmac object (key) and the request content (xml). */
		CryptoPP::StringSource(
			request_->get_content(),
			true,
			new CryptoPP::HashFilter(
				hmac,
				new CryptoPP::StringSink(mac)
			)
		);

		/* Transform mac from binary to lower case hex. */
		CryptoPP::StringSource(
			mac,
			true,
			new CryptoPP::HexEncoder(
				new CryptoPP::StringSink(hex_mac),
				false
			)
		);

		/* Compare given mac with expected mac. */
		return (request_->get_signature() == hex_mac);
	} catch(const CryptoPP::Exception& e) {
		/* Something went wrong, so the authentication was not successful. */
		return false;
	}
}

bool swd::request_handler::decode() {
	/**
	 * The daemon could crash if the json string is somehow invalid, so it is a
	 * very good idea to catch exceptions.
	 */
	try {
		Json::Value root;
		Json::Reader reader;

		if (!reader.parse(request_->get_content(), root)) {
			return false;
		}

		/* If root is not an object the input is invalid. */
		if (!root.isObject()) {
			return false;
		}

		/* First we set the client ip. It shouldn't be possible that this is empty. */
		Json::Value client_ip = root["client_ip"];

		if (!client_ip) {
			return false;
		}

		request_->set_client_ip(client_ip.asString());

		/* The same is true for the caller, the target script on the observed system. */
		Json::Value caller = root["caller"];

		if (!caller) {
			return false;
		}

		request_->set_caller(caller.asString());

		/* For backwards compatibility it is acceptable that the resource is empty. */
		Json::Value resource = root["resource"];

		if (!resource) {
			resource = "";
		}

		request_->set_resource(resource.asString());

		/* Even if there is no user input there should be at least an empty array. */
		Json::Value input = root["input"];

		if (!input) {
			return false;
		}

		/* Iterate over the input and add it to the request as parameters. */
		for (Json::ValueIterator it_parameter = input.begin();
		 it_parameter != input.end(); it_parameter++) {
			try {
				request_->add_parameter(
					it_parameter.key().asString(),
					(*it_parameter).asString()
				);
			} catch (std::runtime_error& e) {
				swd::log::i()->send(swd::uncritical_error, e.what());
			}
		}
	} catch (...) {
		swd::log::i()->send(swd::uncritical_error, "Uncaught json decode exception");
		return false;
	}

	return true;
}

std::vector<std::string> swd::request_handler::process() {
	/* Analyze the request with the black- and whitelist. */
	swd::analyzer analyzer(request_);
	analyzer.start();

	/**
	 * Nothing to do if there are no threats and learning is disabled. If there
	 * is at least one threat or if learning is enabled the complete request gets
	 * recorded permanently.
	 */
	if (request_->has_threats() || request_->get_profile()->is_learning_enabled()) {
		swd::storage::i()->add(request_);
	}

	/**
	 * Return the paths of all threats for the reply. But only if learning mode is
	 * not enabled, because this values are used to defuse a request and this
	 * could result in unusable sites.
	 */
	std::vector<std::string> threats;

	if (!request_->get_profile()->is_learning_enabled()) {
		swd::parameters& parameters = request_->get_parameters();

		for (swd::parameters::iterator it_parameter = parameters.begin();
		 it_parameter != parameters.end(); it_parameter++) {
			/* Save the iterators in variables for the sake of readability. */
			swd::parameter_ptr parameter((*it_parameter).second);

			if (parameter->is_threat()) {
				threats.push_back((*it_parameter).first);
			}
		}
	}

	return threats;
}
