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

#ifndef PARAMETER_H
#define PARAMETER_H

#include <vector>
#include <string>
#include <boost/shared_ptr.hpp>

#include "blacklist_filter.h"
#include "whitelist_rule.h"

namespace swd {
    /**
     * @brief Models a parameter.
     */
    class parameter {
        public:
            /**
             * @brief Set the path of the parameter.
             *
             * @param path The path of the parameter
             */
            void set_path(const std::string& path);

            /**
             * @brief Get the path of the parameter.
             *
             * @return The path of the parameter
             */
            std::string get_path() const;

            /**
             * @brief Get the value of the parameter.
             *
             * @param value The raw value of the parameter
             */
            void set_value(const std::string& value);

            /**
             * @brief Get the value of the parameter.
             *
             * @return The raw value of the parameter
             */
            std::string get_value() const;

            /**
             * @brief Add a (matching) blacklist filter to this parameter.
             *
             * @param filter The pointer to the blacklist filter object
             */
            void add_blacklist_filter(const swd::blacklist_filter_ptr& filter);

            /**
             * @brief Get all (matching) blacklist filters.
             *
             * @return The list of saved blacklist filters
             */
            const swd::blacklist_filters& get_blacklist_filters() const;

            /**
             * @brief Add a (broken) whitelist rule to this parameter.
             *
             * @param rule The pointer to the whitelist rule object
             */
            void add_whitelist_rule(const swd::whitelist_rule_ptr& rule);

            /**
             * @brief Get all (broken) whitelist rules.
             *
             * @return The list of saved whitelist rules
             */
            const swd::whitelist_rules& get_whitelist_rules() const;

            /**
             * @brief Get the total impact of all broken blacklist filters.
             *
             * @return The total impact of all broken blacklist filters.
             */
            unsigned int get_impact() const;

            /**
             * @brief Define if this parameter is a threat or not.
             *
             * @param threat Threat status of this parameter
             */
            void set_threat(const bool& threat);

            /**
             * @brief Check if the parameter is a threat.
             *
             * @return True if the parameter is a threat
             */
            bool is_threat() const;

            /**
             * @brief Define if this parameter has a critical blacklist impact or not.
             *
             * @param critical Critical impact status of this parameter
             */
            void set_critical_blacklist_impact(const bool& critical);

            /**
             *@brief  Check if the parameter has a critical blacklist impact.
             *
             * @return True if the parameter has a critical blacklist impact
             */
            bool has_critical_blacklist_impact() const;

            /**
             * @brief Set the number of whitelist rules.
             *
             * Parameters with not whitelist rule are also classified as an
             * attack, so we have to keep track of the responsible rules.
             */
            void set_total_whitelist_rules(const int& total_whitelist_rules);

            /**
             * @brief Get the total number of responsible whitelist rules.
             *
             * @return The total number of checked whitelist rules
             */
            int get_total_whitelist_rules() const;

        private:
            /**
             * @brief The path/key of the parameter.
             */
            std::string path_;

            /**
             * @brief The value of the parameter.
             */
            std::string value_;

            /**
             * @brief Matching blacklist filters for the value of the parameter.
             */
            swd::blacklist_filters blacklist_filters_;

            /**
             * @brief Broken whitelist rules for they path of the parameter.
             */
            swd::whitelist_rules whitelist_rules_;

            /**
             * @brief The threat status of the parameter.
             */
            bool threat_ = false;

            /**
             * @brief The status of the impact compared to the threshold.
             */
            bool critical_blacklist_impact_ = false;

            /**
             * @brief The total number of matching whitelist rules.
             */
            int total_whitelist_rules_ = 0;
    };

    /**
     * @brief Parameter pointer.
     */
    using parameter_ptr = boost::shared_ptr<swd::parameter>;

    /**
     * @brief Map of parameter pointers. The key is the path.
     */
    using parameters = std::vector<swd::parameter_ptr>;
}

#endif /* PARAMETER_H */
