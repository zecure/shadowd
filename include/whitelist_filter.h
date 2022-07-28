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

#ifndef WHITELIST_FILTER_H
#define WHITELIST_FILTER_H

#include <vector>
#include <string>
#include <boost/regex.hpp>
#include <boost/shared_ptr.hpp>

namespace swd {
    /**
     * @brief Models a whitelist filter.
     *
     * A whitelist filter is used to classify the character set of a parameter.
     * Every whitelist rule points to one of the whitelist filters.
     */
    class whitelist_filter {
        public:
            /**
             * @brief Set the id the filter.
             *
             * @param id The database id of the filter
             */
            void set_id(const unsigned long long& id);

            /**
             * @brief Get the id the filter.
             *
             * @return The id of the filter
             */
            unsigned long long get_id() const;

            /**
             * @brief Set the regular expression of the filter.
             *
             * @param regex The regular expression of the filter
             */
            void set_regex(const std::string& regex);

            /**
             * @brief Test for input if the filter matches.
             *
             * @param input The string that should be tested
             * @return The status of the regular expression test
             */
            bool matches(const std::string& input) const;

        private:
            /**
             * @brief The database id of the filter.
             */
            unsigned long long id_;

            /**
             * @brief The regular expression of the filter.
             */
            boost::regex regex_;
    };

    /**
     * @brief Whitelist filter pointer.
     */
    using whitelist_filter_ptr = boost::shared_ptr<swd::whitelist_filter>;

    /**
     * @brief List of whitelist filter pointers.
     */
    using whitelist_filters = std::vector<swd::whitelist_filter_ptr>;
}

#endif /* WHITELIST_FILTER_H */
