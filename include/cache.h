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

#ifndef CACHE_H
#define CACHE_H

#include <map>
#include <tuple>
#include <boost/thread/mutex.hpp>
#include <boost/shared_ptr.hpp>

#include "database.h"
#include "blacklist_rule.h"

namespace swd {
	/**
	 * @brief Tuple of integer and string.
	 */
	typedef std::tuple<int, std::string> tuple_is;

	/**
	 * @brief Tuple of integer and two strings.
	 */
	typedef std::tuple<int, std::string, std::string> tuple_iss;

	/**
	 * @brief Interface to the database that caches results.
	 */
	class cache {
		public:
			/**
			 * @brief Construct the cache.
			 *
			 * @param database The pointer to the database object
			 */
			cache(const swd::database_ptr& database);

			/**
			 * @brief Removes all elements from the cache.
			 */
			void reset();

			/**
			 * @brief Get blacklist rules.
			 *
			 * @param profile_id The profile id of the request
			 * @param caller The caller (php file) that initiated the connection
			 * @param path The path of the parameter
			 * @return The corresponding table rows
			 */
			swd::blacklist_rules get_blacklist_rules(const int& profile_id,
			 const std::string& caller, const std::string& path);

			/**
			 * @brief Get all blacklist filters.
			 *
			 * @return The corresponding table rows
			 */
			swd::blacklist_filters get_blacklist_filters();

			/**
			 * @brief Get whitelist rules.
			 *
			 * @param profile_id The profile id of the request
			 * @param caller The caller (resource) that initiated the connection
			 * @param path The path of the parameter
			 * @return The corresponding table rows
			 */
			swd::whitelist_rules get_whitelist_rules(const int& profile_id,
			 const std::string& caller, const std::string& path);

			/**
			 * @brief Get integrity rules.
			 *
			 * @param profile_id The profile id of the request
			 * @param caller The caller (resource) that initiated the connection
			 */
			swd::integrity_rules get_integrity_rules(const int& profile_id,
			 const std::string& caller);

		private:
			/**
			 * @brief The pointer to the database object.
			 */
			swd::database_ptr database_;

			/**
			 * @brief The cache map for blacklist rules.
			 */
			std::map<swd::tuple_iss, swd::blacklist_rules> blacklist_rules_;

			/**
			 * @brief The cache vector for blacklist filters.
			 */
			swd::blacklist_filters blacklist_filters_;

			/**
			 * @brief The cache map for whitelist rules.
			 */
			std::map<swd::tuple_iss, swd::whitelist_rules> whitelist_rules_;

			/**
			 * @brief The cache map for integrity rules.
			 */
			std::map<swd::tuple_is, swd::integrity_rules> integrity_rules_;

			/**
			 * @brief The mutex for the blacklist rules.
			 */
			boost::mutex blacklist_rules_mutex_;

			/**
			 * @brief The mutex for the blacklist filters.
			 */
			boost::mutex blacklist_filters_mutex_;

			/**
			 * @brief The mutex for the whitelist rules.
			 */
			boost::mutex whitelist_rules_mutex_;

			/**
			 * @brief The mutex for the integrity rules.
			 */
			boost::mutex integrity_rules_mutex_;
	};

	/**
	 * @brief Cache pointer.
	 */
	typedef boost::shared_ptr<swd::cache> cache_ptr;
}

#endif /* CACHE_H */
