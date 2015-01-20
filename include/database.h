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

#ifndef DATABASE_H
#define DATABASE_H

#include <string>
#include <vector>
#include <boost/shared_ptr.hpp>
#include <dbi/dbi.h>
#include <pthread.h>

#include "profile.h"
#include "whitelist_rule.h"
#include "whitelist_filter.h"
#include "blacklist_rule.h"
#include "blacklist_filter.h"
#include "singleton.h"
#include "shared.h"

namespace swd {
	/**
	 * @brief Encapsulates and handles the database communication.
	 *
	 * There is one database connection for the complete daemon. This is not
	 * perfect, but libdbi does not seem to be thread safe. This is also the
	 * reason why the database queries are protected with mutexes.
	 */
	class database :
	 public swd::singleton<swd::database> {
		public:
			/**
			 * @brief Open a database connection.
			 *
			 * This method tries to establish a database connection and throws
			 * an exception if it is not possible.
			 *
			 * @param driver The database driver, originating from the config
			 * @param host The database host, originating from the config
			 * @param port The database port, originating from the config
			 * @param username The database user, originating from the config
			 * @param password The database password, originating from the config
			 * @param name The database name, originating from the config
			 * @param encoding The database encoding, originating from the config
			 */
			void connect(std::string driver, std::string host, std::string port,
			 std::string username, std::string password, std::string name,
			 std::string encoding);

			/**
			 * @brief Close the database connection.
			 *
			 * This method closes conn_ and shutdowns instance_. It is not in
			 * use at the moment.
			 */
			void disconnect();

			/**
			 * @brief Ensure that the database connection is still open.
			 *
			 * This method tests the database connection and tries to reconnect
			 * if the connection is closed. The manual of libdbi states that some
			 * drivers attempt to reconnect automatically if dbi_conn_ping is called,
			 * but this does not seem to be the norm.
			 */
			void ensure_connection();

			/**
			 * @brief Get a profile by the server ip.
			 *
			 * Since a single shadowd instance can observe multiple different
			 * web servers at once it is necessary to separate the data.
			 * Some data can also vary from profile to profile like the hmac
			 * key or the blacklist impact threshold.
			 *
			 * @param server_ip The ip of the httpd server/shadowd client
			 * @param profile_id The database id of the profile
			 * @return The corresponding table row
			 */
			swd::profile_ptr get_profile(std::string server_ip, int profile_id);

			/**
			 * @brief Get blacklist rules by the profile and caller.
			 *
			 * @param profile The profile id of the request
			 * @param caller The caller (php file) that initiated the connection
			 * @param path The path of the parameter
			 * @return The corresponding table rows
			 */
			swd::blacklist_rules get_blacklist_rules(int profile, std::string caller,
			 std::string path);

			/**
			 * @brief Get all blacklist filters.
			 *
			 * @return The corresponding table rows
			 */
			swd::blacklist_filters get_blacklist_filters();

			/**
			 * @brief Get whitelist rules by the profile and caller.
			 *
			 * @param profile The profile id of the request
			 * @param caller The caller (resource) that initiated the connection
			 * @param path The path of the parameter
			 * @return The corresponding table rows
			 */
			swd::whitelist_rules get_whitelist_rules(int profile, std::string caller,
			 std::string path);

			/**
			 * @brief Save information about a request.
			 *
			 * @param profile The profile id of the request
			 * @param caller The caller (php file) that initiated the connection
			 * @param learning The status of the learning mode
			 * @param client_ip The ip of the attacker
			 * @return The id of the new row
			 */
			int save_request(int profile, std::string caller, int learning,
			 std::string client_ip);

			/**
			 * @brief Save information about a parameter.
			 *
			 * @param request The id of the corresponding request
			 * @param path The path (i.e. key) of the parameter
			 * @param value The value of the parameter
			 * @param total_rules The total number of whitelist rules that are
			 *  responsible for this parameter
			 * @param critical_impact The status of the blacklist test
			 * @param threat The status of the analyzer
			 * @return The id of the new row
			 */
			int save_parameter(int request, std::string path, std::string value,
			 int total_rules, int critical_impact, int threat);

			/**
			 * @brief Add a many to many connector for a matching blacklist filter.
			 *
			 * @param filter The id of the blacklist filter
			 * @param parameter The id of the parameter
			 */
			void add_blacklist_parameter_connector(int filter, int parameter);

			/**
			 * @brief Add a many to many connector for a broken whitelist rule.
			 *
			 * @param rule The id of the whitelist rule
			 * @param parameter The id of the parameter
			 */
			void add_whitelist_parameter_connector(int rule, int parameter);

		private:
			dbi_conn conn_;
#if defined(HAVE_DBI_NEW)
			dbi_inst instance_;
#endif /* defined(HAVE_DBI_NEW) */
			pthread_mutex_t dbi_conn_query_lock;
	};
}

#endif /* DATABASE_H */
