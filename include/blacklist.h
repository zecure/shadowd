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

#ifndef BLACKLIST_H
#define BLACKLIST_H

#include "request.h"
#include "blacklist_filter.h"

namespace swd {
	/**
	 * @brief Handles the blacklist examination of a request.
	 */
	class blacklist {
		public:
			/**
			 * @brief Construct the blacklist. Initialize the blacklist filters
			 *  once to cache them for the life time of this request.
			 *
			 * @param request The pointer to the request object
			 */
			blacklist(swd::request_ptr request);

			/**
			 * @brief Scan all parameters in the request and add connections to
			 *  matching filters.
			 */
			void scan();

		private:
			swd::request_ptr request_;
			swd::blacklist_filters filters_;
	};
}

#endif /* BLACKLIST_H */
