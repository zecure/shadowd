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

#ifndef BLACKLIST_RULE_H
#define BLACKLIST_RULE_H

#include <string>
#include <vector>
#include <boost/shared_ptr.hpp>

namespace swd {
	/**
	 * @brief Models a blacklist rule.
	 */
	class blacklist_rule {
		public:
			/**
			 * @brief Construct a blacklist rule.
			 *
			 * @param id The id of the rule
			 * @param threshold The threshold of the rule
			 */
			blacklist_rule(int id, int threshold);

			/**
			 * @brief Get the id the rule.
			 *
			 * @return The id of the rule
			 */
			int get_id();

			/**
			 * @brief Get the threshold of the rule.
			 *
			 * @return The threshold of the rule
			 */
			int get_threshold();

		private:
			int id_;
			int threshold_;
	};

	/**
	 * @brief Blacklist rule pointer.
	 */
	typedef boost::shared_ptr<swd::blacklist_rule> blacklist_rule_ptr;

	/**
	 * @brief List of blacklist rule pointers.
	 */
	typedef std::vector<swd::blacklist_rule_ptr> blacklist_rules;
}

#endif /* BLACKLIST_RULE_H */
