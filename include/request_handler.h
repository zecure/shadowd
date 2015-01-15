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

#ifndef REQUEST_HANDLER_H
#define REQUEST_HANDLER_H

#include <string>
#include <vector>

#include "request.h"

namespace swd {
	/**
	 * @brief Handles a request object.
	 */
	class request_handler {
		public:
			/**
			 * @brief Construct a request handler.
			 *
			 * @param request The pointer to the request object
			 */
			request_handler(swd::request_ptr request);

			/**
			 * @brief Check if the signature of the request is valid.
			 *
			 * @return Status of hmac check
			 */
			bool valid_signature();

			/**
			 * @brief Decode the json string.
			 *
			 * @return Status of decoding
			 */
			bool decode();

			/**
			 * @brief Start the real processing of the request.
			 *
			 * @return A list of all paths that should be protected
			 */
			std::vector<std::string> process();

		private:
			swd::request_ptr request_;
	};
}

#endif /* REQUEST_HANDLER_H */
