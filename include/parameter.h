/**
 * Shadow Daemon -- Web Application Firewall
 *
 *   Copyright (C) 2014 Hendrik Buchwald <hb@zecure.org>
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
 */

#ifndef PARAMETER_H
#define PARAMETER_H

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
			 * @brief Construct a parameter.
			 *
			 * @param value The raw value of the parameter
			 */
			parameter(std::string value);

			/**
			 * @brief Get the value of the parameter.
			 *
			 * @return The raw value of the parameter
			 */
			std::string get_value();

			/**
			 * @brief Add a (matching) blacklist filter to this parameter.
			 *
			 * @param filter The pointer to the blacklist filter object
			 */
			void add_blacklist_filter(swd::blacklist_filter_ptr filter);

			/**
			 * @brief Get all (matching) blacklist filters.
			 *
			 * @return The list of saved blacklist filters
			 */
			const swd::blacklist_filters& get_blacklist_filters();

			/**
			 * @brief Add a (broken) whitelist rule to this parameter.
			 *
			 * @param rule The pointer to the whitelist rule object
			 */
			void add_whitelist_rule(swd::whitelist_rule_ptr rule);

			/**
			 * @brief Get all (broken) whitelist rules.
			 *
			 * @return The list of saved whitelist rules
			 */
			const swd::whitelist_rules& get_whitelist_rules();

			/**
			 * @brief Get the total impact of all broken blacklist filters.
			 *
			 * @return The total impact of all broken blacklist filters.
			 */
			int get_impact();

			/**
			 * @brief Define if this parameter is a threat or not.
			 *
			 * @param threat Threat status of this parameter
			 */
			void is_threat(bool threat);

			/**
			 * @brief Check if the parameter is a threat.
			 *
			 * @return True if the parameter is a threat
			 */
			bool is_threat();

			/**
			 * @brief Define if this parameter has a critical blacklist impact or not.
			 *
			 * @param critical Critical impact status of this parameter
			 */
			void has_critical_impact(bool critical);

			/**
			 *@brief  Check if the parameter has a critical blacklist impact.
			 *
			 * @return True if the parameter has a critical blacklist impact
			 */
			bool has_critical_impact();

			/**
			 * @brief Set the number of whitelist rules.
			 *
			 * Parameters with not whitelist rule are also classified as an
			 * attack, so we have to keep track of the responsible rules.
			 */
			void set_total_rules(int total_rules);

			/**
			 * @brief Get the total number of responsible whitelist rules.
			 *
			 * @return The total number of checked whitelist rules
			 */
			int get_total_rules();

		private:
			std::string value_;
			swd::blacklist_filters filters_;
			swd::whitelist_rules rules_;
			bool threat_;
			bool critical_impact_;
			int total_rules_;
	};

	/**
	 * @brief Parameter pointer.
	 */
	typedef boost::shared_ptr<swd::parameter> parameter_ptr;

	/**
	 * @brief Map of parameter pointers. The key is the path.
	 */
	typedef std::map<std::string, swd::parameter_ptr> parameters;
}

#endif /* PARAMETER_H */
