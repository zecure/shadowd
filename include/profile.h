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

#ifndef PROFILE_H
#define PROFILE_H

#include <string>
#include <boost/shared_ptr.hpp>

namespace swd {
	/**
	 * @brief Models a profile.
	 */
	class profile {
		public:
			/**
			 * @brief Construct a profile.
			 *
			 * @param server_ip The ip of the http server/shadowd client
			 * @param id The id of the profile
			 * @param mode The status of the system
			 * @param whitelist_enabled The status of the whitelist analyzer
			 * @param blacklist_enabled The status of the blacklist analyzer
			 * @param integrity_enabled The status of the integrity analyzer
			 * @param flooding_enabled The status of the flooding analyzer
			 * @param key The key for the hmac check
			 * @param blacklist_threshold The global threshold for blacklist
			 */
			profile(std::string server_ip, int id, int mode, bool whitelist_enabled,
			 bool blacklist_enabled, bool integrity_enabled, bool flooding_enabled,
			 std::string key, int blacklist_threshold);

			/**
			 * @brief Get the ip of the http server/shadowd client.
			 *
			 * @return The server ip
			 */
			std::string get_server_ip();

			/**
			 * @brief Get the id the profile.
			 *
			 * @return The id of the profile
			 */
			int get_id();

			/**
			 * @brief Get the status of the system.
			 *
			 * @return The status of the system
			 */
			int get_mode();

			/**
			 * @brief Get the status of the whitelist check for the profile.
			 *
			 * @return The whitelist check status
			 */
			bool is_whitelist_enabled();

			/**
			 * @brief Get the status of the blacklist check for the profile.
			 *
			 * @return The blacklist check status
			 */
			bool is_blacklist_enabled();

			/**
			 * @brief Get the status of the integrity check for the profile.
			 *
			 * @return The integrity check status
			 */
			bool is_integrity_enabled();

			/**
			 * @brief Get the status of the flooding check for the profile.
			 *
			 * @return The flooding check status
			 */
			bool is_flooding_enabled();

			/**
			 * @brief Get the key/password for the profile.
			 *
			 * The key gets used by the request handler to check the signature
			 * of the request. This way the key is never send over the wire.
			 * Replay attacks are of course theoretical possible, but if you
			 * can not trust your network you really should use SSL anyway.
			 *
			 * @return The hmac key the client has to use
			 */
			std::string get_key();

			/**
			 * @brief Get the global blacklist threshold for the profile.
			 *
			 * The threshold is used by the analyzer to check if the blacklist
			 * impact is so high that the parameter should be classified as an
			 * attack.
			 *
			 * @return The blacklist threshold
			 */
			int get_blacklist_threshold();

		private:
			std::string server_ip_;
			int id_;
			int mode_;
			bool whitelist_enabled_;
			bool blacklist_enabled_;
			bool integrity_enabled_;
			bool flooding_enabled_;
			std::string key_;
			int blacklist_threshold_;

	};

	/**
	 * @brief Profile pointer.
	 */
	typedef boost::shared_ptr<swd::profile> profile_ptr;
}

#endif /* PROFILE_H */
