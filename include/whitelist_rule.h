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

#ifndef WHITELIST_RULE_H
#define WHITELIST_RULE_H

#include <vector>
#include <string>
#include <boost/shared_ptr.hpp>

#include "whitelist_filter.h"

namespace swd {
    /**
     * @brief Models a whitelist rule.
     */
    class whitelist_rule {
        public:
            /**
             * @brief Set the id of the rule.
             *
             * @param id The id of the rule
             */
            void set_id(const unsigned long long& id);

            /**
             * @brief Get the id of the rule.
             *
             * @return The id of the rule
             */
            unsigned long long get_id() const;

            /**
             * @brief Set the whitelist filter of the rule.
             *
             * @param filter The whitelist filter of the rule
             */
            void set_filter(const swd::whitelist_filter_ptr& filter);

            /**
             * @brief Set the minimum length of the rule.
             *
             * @param min_length The minimum length of the rule
             */
            void set_min_length(const int& min_length);

            /**
             * @brief Set the maximum length of the rule.
             *
             * @param max_length The maximum length of the rule
             */
            void set_max_length(const int& max_length);

            /**
             * @brief Test for value if the filter matches and if the length is
             *  acceptable.
             *
             * @param value The string that should be tested
             * @return The status of the regular expression and length test
             */
            bool is_adhered_to(const std::string& value) const;

        private:
            /**
             * @brief The database id of the rule.
             */
            unsigned long long id_;

            /**
             * @brief The pointer to the whitelist filter.
             */
            swd::whitelist_filter_ptr filter_;

            /**
             * @brief The minimum length of the input.
             */
            int min_length_;

            /**
             * @brief The maximum length of the input.
             */
            int max_length_;
    };

    /**
     * @brief Whitelist rule pointer.
     */
    using whitelist_rule_ptr = boost::shared_ptr<swd::whitelist_rule>;

    /**
     * @brief List of whitelist rule pointers.
     */
    using whitelist_rules = std::vector<swd::whitelist_rule_ptr>;
}

#endif /* WHITELIST_RULE_H */
