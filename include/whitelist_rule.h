/**
 * Shadow Daemon -- High-Interaction Web Honeypot
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

#ifndef RULE_H
#define RULE_H

#include <string>
#include <vector>
#include <boost/shared_ptr.hpp>
#include <boost/regex.hpp>
#include <boost/algorithm/string/replace.hpp>

#include "whitelist_filter.h"

namespace swd {
	/**
	 * @brief Models a whitelist rule.
	 *
	 * If is_responsible() is true it is required that is_adhered_to() is also
	 * true, otherwise the input parameter is classified as an attack.
	 * Parameters are directly connected with broken rules.
	 */
	class whitelist_rule {
		public:
			/**
			 * @brief Construct a whitelist rule.
			 *
			 * @param id The id of the rule
			 * @param path The path of the rule
			 * @param filter The whitelist filter of the rule
			 * @param min_length The minimum length of the rule
			 * @param max_length The maximum length of the rule
			 */
			whitelist_rule(int id, std::string path, swd::whitelist_filter_ptr filter,
			 int min_length, int max_length);

			/**
			 * @brief Get the id the rule.
			 *
			 * @return The id of the rule
			 */
			int get_id();

			/**
			 * @brief Test for path if the rule should handle the parameter.
			 *
			 * @param path The string that should be tested
			 * @return The status of the responsibility test
			 */
			bool is_responsible(std::string path);

			/**
			 * @brief Test for value if the filter matches and if the length is
			 *  acceptable.
			 *
			 * @param value The string that should be tested
			 * @return The status of the regular expression and length test
			 */
			bool is_adhered_to(std::string value);

		private:
			void escape_regex(std::string &regex);
			int id_;
			boost::regex path_;
			swd::whitelist_filter_ptr filter_;
			int min_length_;
			int max_length_;
	};

	/**
	 * @brief Whitelist rule pointer.
	 */
	typedef boost::shared_ptr<swd::whitelist_rule> whitelist_rule_ptr;

	/**
	 * @brief List of whitelist rule pointers.
	 */
	typedef std::vector<swd::whitelist_rule_ptr> whitelist_rules;
}

#endif /* RULE_H */
