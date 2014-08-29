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

#ifndef BLACKLIST_FILTER_H
#define BLACKLIST_FILTER_H

#include <vector>
#include <string>
#include <boost/regex.hpp>

namespace swd {
	/**
	 * @brief Models a blacklist filter.
	 *
	 * This class and its regular expressions are based on PHPIDS.
	 * Parameters are directly connected with matching filters if the request
	 * is classified as an attack or if learning mode is enabled.
	 */
	class blacklist_filter {
		public:
			/**
			 * @brief Construct a blacklist filter.
			 *
			 * @param id The database id of the filter
			 * @param rule The regular expression of the filter
			 * @param impact The dangerousness of the filter
			 */
			blacklist_filter(int id, std::string rule, int impact);

			/**
			 * @brief Get the id of the filter.
			 *
			 * @return The id of the filter
			 */
			int get_id();

			/**
			 * @brief Get the impact of the filter.
			 *
			 * @return The impact of the filter
			 */
			int get_impact();

			/**
			 * @brief Test for input if the filter matches.
			 *
			 * @param input The string that should be tested
			 * @return The status of the regular expression test
			 */
			bool match(std::string input);

		private:
			int id_;
			int impact_;
			boost::regex rule_;
	};

	/**
	 * @brief Blacklist filter pointer.
	 */
	typedef boost::shared_ptr<swd::blacklist_filter> blacklist_filter_ptr;

	/**
	 * @brief List of blacklist filter pointers.
	 */
	typedef std::vector<swd::blacklist_filter_ptr> blacklist_filters;
}

#endif /* BLACKLIST_FILTER_H */
