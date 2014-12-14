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

#ifndef REPLY_H
#define REPLY_H

#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>

#include "shared.h"

namespace swd {
	/**
	 * @brief Models a reply.
	 */
	class reply {
		public:
			/**
			 * @brief Set the status code of the reply.
			 *
			 * @param status The status code of the reply
			 */
			void set_status(int status);

			/**
			 * @brief Get the status code of the reply.
			 *
			 * @return The status code of the reply
			 */
			int get_status();

			/**
			 * @brief Set a list of threat paths.
			 *
			 * @param threats A list of paths strings of parameters that were
			 *  classified as threats.
			 */
			void set_threats(std::vector<std::string> threats);

			/**
			 * @brief Get the list of threat paths.
			 */
			std::vector<std::string> get_threats();

			/**
			 * @brief Set the content that gets send back to the http server.
			 *
			 * @param content The output content
			 */
			void set_content(std::string content);

			/**
			 * @brief Convert the reply into a vector of buffers.
			 *
			 * The buffers do not own the underlying memory blocks, therefore
			 * the reply object must remain valid and not be changed until the
			 * write operation has completed.
			 *
			 * @return The output that gets send back to the http server
			 */
			std::vector<boost::asio::const_buffer> to_buffers();

		private:
			int status_;
			std::vector<std::string> threats_;
			std::string content_;
	};

	/**
	 * @brief Reply pointer.
	 */
	typedef boost::shared_ptr<swd::reply> reply_ptr;
}

#endif /* REPLY_H */
