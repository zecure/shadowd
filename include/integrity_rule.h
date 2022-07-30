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

#ifndef INTEGRITY_RULE_H
#define INTEGRITY_RULE_H

#include <vector>
#include <string>
#include <boost/shared_ptr.hpp>

#include "hash.h"

namespace swd {
    /**
     * @brief Models an integrity rule.
     */
    class integrity_rule {
        public:
            /**
             * @brief Set the id the rule.
             *
             * @param id The id of the rule
             */
            void set_id(const unsigned long long& id);

            /**
             * @brief Get the id the rule.
             *
             * @return The id of the rule
             */
            unsigned long long get_id() const;

            /**
             * @brief Set the hash algorithm of the rule
             *
             * @param algorithm The hash algorithm of the rule
             */
            void set_algorithm(const std::string& algorithm);

            /**
             * @brief Get the hash algorithm of the rule
             *
             * @return The hash algorithm of the rule
             */
            std::string get_algorithm() const;

            /**
             * @brief Set the hash digest of the rule
             *
             * @param digest The hash digest of the rule
             */
            void set_digest(const std::string& digest);

            /**
             * @brief Get the hash digest of the rule
             *
             * @return The hash digest of the rule
             */
            std::string get_digest() const;

            /**
             * @brief Checks if the hash matches the rule.
             *
             * @param hash The pointer to the hash object that should be checked.
             */
            bool matches(const swd::hash_ptr& hash) const;

        private:
            /**
             * @brief The database id of the rule.
             */
            unsigned long long id_;

            /**
             * @brief The algorithm of the rule.
             */
            std::string algorithm_;

            /**
             * @brief The digest of the rule.
             */
            std::string digest_;
    };

    /**
     * @brief Integrity rule pointer.
     */
    using integrity_rule_ptr = boost::shared_ptr<swd::integrity_rule>;

    /**
     * @brief List of integrity rule pointers.
     */
    using integrity_rules = std::vector<swd::integrity_rule_ptr>;
}

#endif /* INTEGRITY_RULE_H */
