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

#ifndef REPLY_HANDLER_H
#define REPLY_HANDLER_H

#include "reply.h"

namespace swd {
	/**
	 * @brief Prepares a reply before it can be send to the client.
	 */
	class reply_handler {
		public:
			/**
			 * @brief Construct a reply handler.
			 *
			 * @param reply The pointer to the reply object
			 */
			reply_handler(swd::reply_ptr reply);

			/**
			 * @brief Encode the content of the reply with json and save the encoded
			 *  version also in the reply.
			 *
			 * @return The status of the json encoding
			 */
			bool encode();

		private:
			swd::reply_ptr reply_;
	};
}

#endif /* REPLY_HANDLER_H */
