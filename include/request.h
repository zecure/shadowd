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

#ifndef REQUEST_H
#define REQUEST_H

#include <string>
#include <vector>
#include <map>
#include <boost/shared_ptr.hpp>

#include "profile.h"
#include "parameter.h"

namespace swd {
	/**
	 * @brief Models a request.
	 *
	 * In contrast to most other model classes in this project the request does
	 * not have all of his information at the time of construction. Instead first
	 * the signature and raw content get appended character by character. After
	 * that is done the signature gets checked and the raw content gets decoded.
	 * If there was no error this is the point where the request object contains
	 * all of its information in a clear format.
	 */
	class request {
		public:
			/**
			 * @brief Set the pointer of the profile.
			 *
			 * @param profile The profile of the connection
			 */
			void set_profile(swd::profile_ptr profile);

			/**
			 * @brief Get the pointer of the profile.
			 *
			 * @return The profile that got assigned to this request
			 */
			swd::profile_ptr get_profile();

			/**
			 * @brief Add a parameter object to the request.
			 *
			 * @param key The path/key of the parameter
			 * @param value The value of the parameter
			 */
			void add_parameter(std::string key, std::string value);

			/**
			 * @brief Get all saved parameters.
			 *
			 * @return The reference of the parameter list
			 */
			swd::parameters& get_parameters();

			/**
			 * @brief Append a character to the content string.
			 *
			 * This function is used by the request_parser to construct the raw
			 * content character by character.
			 *
			 * @param input The character that gets appended
			 */
			void append_content(char input);

			/**
			 * @brief Get the complete json content.
			 *
			 * @return The complete encoded content.
			 */
			std::string get_content();

			/**
			 * @brief Append a character to the signature string.
			 *
			 * This function is used by the request_parser to construct the raw
			 * signature character by character.
			 *
			 * @param input The character that gets appended
			 */
			void append_signature(char input);

			/**
			 * @brief Get the complete signature.
			 *
			 * @return The complete signature.
			 */
			std::string get_signature();

			/**
			 * @brief Append a character to the profile id.
			 *
			 * This function is used by the request_parser to construct the raw
			 * profile id character by character.
			 *
			 * @param input The character digit that gets appended
			 */
			void append_profile_id(char input);

			/**
			 * @brief Get the complete profile id.
			 *
			 * @return The complete profile id.
			 */
			int get_profile_id();

			/**
			 * @brief Set the http client/attacker ip.
			 *
			 * @param client_ip The ip of the attacker
			 */
			void set_client_ip(std::string client_ip);

			/**
			 * @brief Get the http client/attacker ip.
			 *
			 * @return The ip of the attacker
			 */
			std::string get_client_ip();

			/**
			 * @brief Set the caller of this request.
			 *
			 * @param caller The caller
			 */
			void set_caller(std::string caller);

			/**
			 * @brief Get the caller of this request.
			 *
			 * @return The caller
			 */
			std::string get_caller();

			/**
			 * @brief Check if any parameter of this request is classified by the
			 *  analyzer as a threat.
			 *
			 * This is needed by the storage to check if the request should be stored
			 * on the hard disk or not.
			 *
			 * @return If it is classified as threat
			 */
			bool has_threats();

		private:
			swd::profile_ptr profile_;
			swd::parameters parameters_;
			std::string content_;
			std::string signature_;
			std::string profile_id_;
			std::string client_ip_;
			std::string caller_;
	};

	/**
	 * @brief Request pointer.
	 */
	typedef boost::shared_ptr<swd::request> request_ptr;
}

#endif /* REQUEST_H */
