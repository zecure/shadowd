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

#ifndef DATABASE_H
#define DATABASE_H

#include <string>
#include <boost/thread/mutex.hpp>
#include <boost/shared_ptr.hpp>
#include <dbi/dbi.h>

#include "profile.h"
#include "whitelist_rule.h"
#include "whitelist_filter.h"
#include "blacklist_rule.h"
#include "blacklist_filter.h"
#include "integrity_rule.h"
#include "shared.h"

namespace swd {
    /**
     * @brief Encapsulates and handles the database communication.
     *
     * There is one database connection for the complete daemon. This is not
     * perfect, but libdbi does not seem to be thread safe. This is also the
     * reason why the database queries are protected with mutexes.
     */
    class database {
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
             * @param wait Retry connecting to the database
             */
            void connect(const std::string& driver, const std::string& host,
             const std::string& port, const std::string& username,
             const std::string& password, const std::string& name,
             const std::string& encoding, bool wait);

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
             * if the connection is closed. The manual of libdbi states that
             * some drivers attempt to reconnect automatically if dbi_conn_ping
             * is called, but this does not seem to be the norm.
             */
            void ensure_connection();

            /**
             * @brief Get a profile.
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
            swd::profile_ptr get_profile(const std::string& server_ip,
             const unsigned long long& profile_id);

            /**
             * @brief Get blacklist rules.
             *
             * @param profile The profile id of the request
             * @param caller The caller (php file) that initiated the connection
             * @param path The path of the parameter
             * @return The corresponding table rows
             */
            swd::blacklist_rules get_blacklist_rules(const unsigned long long& profile,
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
             * @param profile The profile id of the request
             * @param caller The caller (resource) that initiated the connection
             * @param path The path of the parameter
             * @return The corresponding table rows
             */
            swd::whitelist_rules get_whitelist_rules(const unsigned long long& profile,
             const std::string& caller, const std::string& path);

            /**
             * @brief Get integrity rules.
             *
             * @param profile The profile id of the request
             * @param caller The caller (resource) that initiated the connection
             */
            swd::integrity_rules get_integrity_rules(const unsigned long long& profile,
             const std::string& caller);

            /**
             * @brief Save information about a request.
             *
             * @param profile_id The profile id of the request
             * @param caller The caller (php file) that initiated the connection
             * @param resource The resource identifier
             * @param mode The status of the system
             * @param client_ip The ip of the attacker
             * @param total_integrity_rules The number of broken integrity rules
             * @return The id of the new row
             */
            unsigned long long save_request(const unsigned long long& profile_id, const std::string& caller,
             const std::string& resource, const unsigned int& mode,
             const std::string& client_ip, const int& total_integrity_rules);

            /**
             * @brief Save information about a parameter.
             *
             * @param request_id The id of the corresponding request
             * @param path The path (i.e. key) of the parameter
             * @param value The value of the parameter
             * @param total_whitelist_rules The total number of whitelist rules
             *  that are responsible for this parameter
             * @param critical_impact The status of the blacklist test
             * @param threat The status of the analyzer
             * @return The id of the new row
             */
            unsigned long long save_parameter(const unsigned long long& request_id, const std::string& path,
             const std::string& value, const int& total_whitelist_rules,
             const int& critical_impact, const int& threat);

            /**
             * @brief Save information about a hash.
             *
             * @param request_id The id of the corresponding request
             * @param algorithm The algorithm that is used to calculate the hash
             * @param digest The output of the hash algorithm on the message
             */
            unsigned long long save_hash(const unsigned long long& request_id, const std::string& algorithm,
             const std::string& digest);

            /**
             * @brief Add a many to many connector for a matching blacklist filter.
             *
             * @param filter_id The id of the blacklist filter
             * @param parameter_id The id of the parameter
             */
            void add_blacklist_parameter_connector(const unsigned long long& filter_id,
             const unsigned long long& parameter_id);

            /**
             * @brief Add a many to many connector for a broken whitelist rule.
             *
             * @param rule_id The id of the whitelist rule
             * @param parameter_id The id of the parameter
             */
            void add_whitelist_parameter_connector(const unsigned long long& rule_id,
             const unsigned long long& parameter_id);

            /**
             * @brief Add a many to many connector for a broken integrity rule.
             *
             * @param rule_id The id of the integrity rule
             * @param request_id The id of the request
             */
            void add_integrity_request_connector(const unsigned long long& rule_id,
             const unsigned long long& request_id);

            /**
             * @brief Get the flooding status of the client.
             *
             * @param client_ip The ip of the client
             * @param profile_id The profile id of the request
             * @return The status of the flooding check
             */
            bool is_flooding(const std::string& client_ip, const unsigned long long& profile_id);

            /**
             * @brief Set the status of the cache for all profiles.
             *
             * @param cache_outdated The status of the cache
             */
            void set_cache_outdated(const bool& cache_outdated);

            /**
             * @brief Set the status of the cache for one profile.
             *
             * @param profile_id The id of the profile
             * @param cache_outdated The status of the cache
             */
            void set_cache_outdated(const unsigned long long& profile_id,
             const bool& cache_outdated);

        private:
            /**
             * @brief The database connection.
             */
            dbi_conn conn_;

            /**
             * @brief The database instance.
             */
#if defined(HAVE_DBI_NEW)
            dbi_inst instance_;
#endif /* defined(HAVE_DBI_NEW) */

            /**
             * @brief The mutex for database access.
             */
            boost::mutex dbi_mutex_;

            /**
             * @brief Remove nullbytes for libdbi.
             */
            std::string remove_null(std::string target);
    };

    /**
     * @brief Database pointer.
     */
    using database_ptr = boost::shared_ptr<swd::database>;
}

#endif /* DATABASE_H */
