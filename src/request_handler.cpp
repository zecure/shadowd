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

swd::request_handler::request_handler(swd::request_ptr request,
 swd::analyzer_ptr analyzer, swd::storage_ptr storage) :
 request_(request),
 analyzer_(analyzer),
 storage_(storage) {
}

bool swd::request_handler::valid_signature() {
	try {
		/* Prepare secret key for hmac. */
		std::string key = request_->get_profile()->get_key();

		CryptoPP::HMAC<CryptoPP::SHA256> hmac(
			(const byte *)key.c_str(),
			key.size()
		);

		/* Transform user mac from lower case hex to binary. */
		std::string mac;

		CryptoPP::StringSource(
			request_->get_signature(),
			true, /* pumpAll */
			new CryptoPP::HexDecoder(
				new CryptoPP::StringSink(mac)
			)
		);

		/* Compare given mac with expected mac. */
		bool result = false;

		CryptoPP::StringSource ss(
			request_->get_content() + mac,
			true, 
			new CryptoPP::HashVerificationFilter(
				hmac,
				new CryptoPP::ArraySink((byte*)&result, sizeof(result)),
				CryptoPP::HashVerificationFilter::PUT_RESULT |
				CryptoPP::HashVerificationFilter::HASH_AT_END
			)
		);

		return result;
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

		/* Iterate over the hashes and add them to the request. */
		Json::Value hashes = root["hashes"];

		if (!hashes) {
			return false;
		}

		for (Json::ValueIterator it_hash = hashes.begin();
		 it_hash != hashes.end(); it_hash++) {
			try {
				request_->add_hash(
					it_hash.key().asString(),
					(*it_hash).asString()
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

void swd::request_handler::process() {
	/* Analyze the request with the black- and whitelist. */
	analyzer_->scan(request_);

	/**
	 * Nothing to do if there are no threats and learning is disabled. If there
	 * is at least one threat or if learning is enabled the complete request gets
	 * recorded permanently.
	 */
	if (request_->get_threat() || request_->has_threats() ||
	 (request_->get_profile()->get_mode() == MODE_LEARNING)) {
		storage_->add(request_);
	}
}

std::vector<std::string> swd::request_handler::get_threats() {
	std::vector<std::string> threats;

	swd::parameters& parameters = request_->get_parameters();

	for (swd::parameters::iterator it_parameter = parameters.begin();
	 it_parameter != parameters.end(); it_parameter++) {
		/* Save the iterators in variables for the sake of readability. */
		swd::parameter_ptr parameter(*it_parameter);

		if (parameter->get_threat()) {
			threats.push_back(parameter->get_path());
		}
	}

	return threats;
}
