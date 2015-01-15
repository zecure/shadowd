/**
 * Shadow Daemon -- Web Application Firewall
 *
 *   Copyright (C) 2014-2015 Hendrik Buchwald <hb@zecure.org>
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

#ifndef WHITELIST_FILTER_H
#define WHITELIST_FILTER_H

#include <vector>
#include <string>
#include <boost/regex.hpp>

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
			 * @brief Construct a whitelist filter.
			 *
			 * @param id The database id of the filter
			 * @param rule The regular expression of the filter
			 */
			whitelist_filter(int id, std::string rule);

			/**
			 * @brief Get the id the filter.
			 *
			 * @return The id of the filter
			 */
			int get_id();

			/**
			 * @brief Test for input if the filter matches.
			 *
			 * @param input The string that should be tested
			 * @return The status of the regular expression test
			 */
			bool match(std::string input);

		private:
			int id_;
			boost::regex rule_;
	};

	/**
	 * @brief Whitelist filter pointer.
	 */
	typedef boost::shared_ptr<swd::whitelist_filter> whitelist_filter_ptr;

	/**
	 * @brief List of whitelist filter pointers.
	 */
	typedef std::vector<swd::whitelist_filter_ptr> whitelist_filters;
}

#endif /* WHITELIST_FILTER_H */
