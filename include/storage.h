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

#ifndef STORAGE_H
#define STORAGE_H

#include <vector>

#include "request.h"

namespace swd {
	/**
	 * @brief Manages the storage of a request.
	 */
	class storage {
		public:
			/**
			 * @brief Save a complete request in the database.
			 *
			 * @param request The pointer to the request object
			 */
			void save(swd::request_ptr request);
	};
}

#endif /* STORAGE_H */
