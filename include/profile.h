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
             * @brief Set the allowed ips of the http server/shadowd client.
             *
             * @param server_ip The allowed ips of the http server/shadowd client
             */
            void set_server_ip(const std::string& server_ip);

            /**
             * @brief Get the ip of the http server/shadowd client.
             *
             * @return The allowed ips of the http server/shadowd clients
             */
            std::string get_server_ip() const;

            /**
             * @brief Set the id the profile.
             *
             * @param id The id of the profile
             */
            void set_id(const unsigned long long& id);

            /**
             * @brief Get the id the profile.
             *
             * @return The id of the profile
             */
            unsigned long long get_id() const;

            /**
             * @brief Set the status of the system.
             *
             * @param mode The status of the system
             */
            void set_mode(const unsigned int& mode);

            /**
             * @brief Get the status of the system.
             *
             * @return The status of the system
             */
            unsigned int get_mode() const;

            /**
             * @brief Set the status of the whitelist check for the profile.
             *
             * @param whitelist_enabled The status of the whitelist analyzer
             */
            void set_whitelist_enabled(const bool& whitelist_enabled);

            /**
             * @brief Get the status of the whitelist check for the profile.
             *
             * @return The whitelist check status
             */
            bool is_whitelist_enabled() const;

            /**
             * @brief Set the status of the blacklist check for the profile.
             *
             * @param blacklist_enabled The status of the blacklist analyzer
             */
            void set_blacklist_enabled(const bool& blacklist_enabled);

            /**
             * @brief Get the status of the blacklist check for the profile.
             *
             * @return The blacklist check status
             */
            bool is_blacklist_enabled() const;

            /**
             * @brief Set the status of the integrity check for the profile.
             *
             * @param integrity_enabled The status of the integrity analyzer
             */
            void set_integrity_enabled(const bool& integrity_enabled);

            /**
             * @brief Get the status of the integrity check for the profile.
             *
             * @return The integrity check status
             */
            bool is_integrity_enabled() const;

            /**
             * @brief Set the status of the flooding check for the profile.
             *
             * @param flooding_enabled The status of the flooding analyzer
             */
            void set_flooding_enabled(const bool& flooding_enabled);

            /**
             * @brief Get the status of the flooding check for the profile.
             *
             * @return The flooding check status
             */
            bool is_flooding_enabled() const;

            /**
             * @brief Set the key/password for the profile.
             *
             * @param key The key for the hmac check
             */
            void set_key(const std::string& key);

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
            std::string get_key() const;

            /**
             * @brief Set the global blacklist threshold for the profile.
             *
             * @param blacklist_threshold The global threshold for blacklist
             */
            void set_blacklist_threshold(const int& blacklist_threshold);

            /**
             * @brief Get the global blacklist threshold for the profile.
             *
             * The threshold is used by the analyzer to check if the blacklist
             * impact is so high that the parameter should be classified as an
             * attack.
             *
             * @return The blacklist threshold
             */
            int get_blacklist_threshold() const;

            /**
             * @brief Set the status of the cache for the profile.
             *
             * @param cache_outdated The status of the cache
             */
            void set_cache_outdated(const bool& cache_outdated);

            /**
             * @brief Get the status of the cache for the profile.
             *
             * @return The status of the cache
             */
            bool is_cache_outdated() const;

        private:
            /**
             * @brief The allowed ips of the http server/shadowd client.
             */
            std::string server_ip_;

            /**
             * @brief The database id of the profile.
             */
            unsigned long long id_;

            /**
             * @brief The mode of the profile.
             */
            unsigned int mode_;

            /**
             * @brief The status of the whitelist check.
             */
            bool whitelist_enabled_;

            /**
             * @brief The status of the blacklist check.
             */
            bool blacklist_enabled_;

            /**
             * @brief The status of the integrity check.
             */
            bool integrity_enabled_;

            /**
             * @brief The status of the flooding check.
             */
            bool flooding_enabled_;

            /**
             * @brief The private key of the profile.
             */
            std::string key_;

            /**
             * @brief The global blacklist threshold of the profile.
             */
            int blacklist_threshold_;

            /**
             * @brief The status of the cache.
             */
            bool cache_outdated_;

    };

    /**
     * @brief Profile pointer.
     */
    using profile_ptr = boost::shared_ptr<swd::profile>;
}

#endif /* PROFILE_H */
