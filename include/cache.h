/**
 * Shadow Daemon -- Web Application Firewall
 *
 *   Copyright (C) 2014-2022 Hendrik Buchwald <hb@zecure.org>
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
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/shared_ptr.hpp>

#include "cached.h"
#include "database.h"
#include "blacklist_rule.h"

namespace swd {
    /**
     * @brief Cached blacklist rules.
     */
    using cached_blacklist_rules = swd::cached<swd::blacklist_rules>;

    /**
     * @brief Pointer to cached blacklist rules.
     */
    using cached_blacklist_rules_ptr = boost::shared_ptr<cached_blacklist_rules>;

    /**
     * @brief Cached whitelist rules.
     */
    using cached_whitelist_rules = swd::cached<swd::whitelist_rules>;

    /**
     * @brief Pointer to cached whitelist rules.
     */
    using cached_whitelist_rules_ptr = boost::shared_ptr<cached_whitelist_rules>;

    /**
     * @brief Cached integrity rules.
     */
    using cached_integrity_rules = swd::cached<swd::integrity_rules>;

    /**
     * @brief Pointer to cached integrity rules.
     */
    using cached_integrity_rules_ptr = boost::shared_ptr<cached_integrity_rules>;

    /**
     * @brief Interface to the database that caches results.
     *
     * This class provides methods with the same names and parameters as the
     * database class. It first checks if the requested data is already saved
     * in the memory. Otherwise it fetches the data automatically from the
     * database and saves them in the memory.
     *
     * It is possible to add values manually to the cache, but this is only
     * intended for the unit tests, since the cache is filled automatically
     * when used normally.
     */
    class cache {
        public:
            /**
             * @brief Construct the cache.
             *
             * @param database The pointer to the database object
             */
            cache(swd::database_ptr database);

            /**
             * @brief Start cleanup thread.
             */
            void start();

            /**
             * @brief Gracefully stop cleanup.
             */
            void stop();

            /**
             * @brief Remove all elements of one profile from the cache.
             *
             * @param profile_id The id of the profile
             */
            void reset_profile(unsigned long long profile_id);

            /**
             * @brief Remove all elements from the cache.
             */
            void reset_all();

            /**
             * @brief Set the blacklist filters. Unit tests only.
             *
             * @param blacklist_filters The vector of blacklist filters
             */
            void set_blacklist_filters(const swd::blacklist_filters&
             blacklist_filters);

            /**
             * @brief Get all blacklist filters.
             *
             * @return The corresponding table rows
             */
            swd::blacklist_filters get_blacklist_filters();

            /**
             * @brief Add whitelist rules to the cache. Unit tests only.
             *
             * @param profile_id The profile id of the request
             * @param caller The caller (php file) that initiated the connection
             * @param path The path of the parameter
             * @param blacklist_rules The vector of blacklist rules
             */
            void add_blacklist_rules(const unsigned long long& profile_id,
             const std::string& caller, const std::string& path,
             const swd::blacklist_rules& blacklist_rules);

            /**
             * @brief Get blacklist rules.
             *
             * @param profile_id The profile id of the request
             * @param caller The caller (php file) that initiated the connection
             * @param path The path of the parameter
             * @return The corresponding table rows
             */
            swd::blacklist_rules get_blacklist_rules(const unsigned long long& profile_id,
             const std::string& caller, const std::string& path);

            /**
             * @brief Add whitelist rules to the cache. Unit tests only.
             *
             * @param profile_id The profile id of the request
             * @param caller The caller (php file) that initiated the connection
             * @param path The path of the parameter
             * @param whitelist_rules The vector of whitelist rules
             */
            void add_whitelist_rules(const unsigned long long& profile_id,
             const std::string& caller, const std::string& path,
             const swd::whitelist_rules& whitelist_rules);

            /**
             * @brief Get whitelist rules.
             *
             * @param profile_id The profile id of the request
             * @param caller The caller (resource) that initiated the connection
             * @param path The path of the parameter
             * @return The corresponding table rows
             */
            swd::whitelist_rules get_whitelist_rules(const unsigned long long& profile_id,
             const std::string& caller, const std::string& path);

            /**
             * @brief Add integrity rules to the cache. Unit tests only.
             *
             * @param profile_id The profile id of the request
             * @param caller The caller (php file) that initiated the connection
             * @param integrity_rules The vector of integrity rules
             */
            void add_integrity_rules(const unsigned long long& profile_id,
             const std::string& caller, const swd::integrity_rules&
             integrity_rules);

            /**
             * @brief Get integrity rules.
             *
             * @param profile_id The profile id of the request
             * @param caller The caller (resource) that initiated the connection
             */
            swd::integrity_rules get_integrity_rules(const unsigned long long& profile_id,
             const std::string& caller);

        private:
            /**
             * @brief Loop over the cached objects and remove outdated elements.
             */
            void cleanup();

            /**
             * @brief The pointer to the database object.
             */
            swd::database_ptr database_;

            /**
             * @brief The cache vector for blacklist filters.
             */
            swd::blacklist_filters blacklist_filters_;

            /**
             * @brief The cache map for blacklist rules.
             */
            std::map< unsigned long long, std::map< std::string, std::map<std::string,
             swd::cached_blacklist_rules_ptr> > > blacklist_rules_;

            /**
             * @brief The cache map for whitelist rules.
             */
            std::map< unsigned long long, std::map< std::string, std::map<std::string,
             swd::cached_whitelist_rules_ptr> > > whitelist_rules_;

            /**
             * @brief The cache map for integrity rules.
             */
            std::map< unsigned long long, std::map<std::string,
             swd::cached_integrity_rules_ptr> > integrity_rules_;

            /**
             * @brief The mutex for the blacklist filters.
             */
            boost::mutex blacklist_filters_mutex_;

            /**
             * @brief The mutex for the blacklist rules.
             */
            boost::mutex blacklist_rules_mutex_;

            /**
             * @brief The mutex for the whitelist rules.
             */
            boost::mutex whitelist_rules_mutex_;

            /**
             * @brief The mutex for the integrity rules.
             */
            boost::mutex integrity_rules_mutex_;

            /**
             * @brief Switch to exit cleanup loop.
             */
            bool stop_ = false;

            /**
             * @brief Thread that constantly checks for outdated elements.
             */
            boost::thread worker_thread_;
    };

    /**
     * @brief Cache pointer.
     */
    using cache_ptr = boost::shared_ptr<swd::cache>;
}

#endif /* CACHE_H */
