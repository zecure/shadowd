/**
 * Shadow Daemon -- Web Application Firewall
 *
 *   Copyright (C) 2014-2022 Hendrik Buchwald <hb@zecure.org>
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

#ifndef REPLY_H
#define REPLY_H

#include <vector>
#include <string>
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
            void set_status(const int& status);

            /**
             * @brief Get the status code of the reply.
             *
             * @return The status code of the reply
             */
            int get_status() const;

            /**
             * @brief Set an optional status message of the reply.
             *
             * @param message The status message of the reply
             */
            void set_message(const std::string& message);

            /**
             * Get the optional status message of the reply.
             *
             * @return The status message of the reply
             */
            std::string get_message() const;

            /**
             * @brief Set a list of threat paths.
             *
             * @param threats A list of paths strings of parameters that were
             *  classified as threats.
             */
            void set_threats(const std::vector<std::string>& threats);

            /**
             * @brief Get the list of threat paths.
             */
            std::vector<std::string> get_threats() const;

            /**
             * @brief Set the content that gets send back to the http server.
             *
             * @param content The output content
             */
            void set_content(const std::string& content);

            /**
             * @brief Get the content that gets send back to the http server.
             *
             * @return The output content
             */
            std::string get_content() const;

            /**
             * @brief Convert the reply into a vector of buffers.
             *
             * The buffers do not own the underlying memory blocks, therefore
             * the reply object must remain valid and not be changed until the
             * write operation has completed.
             *
             * @return The output that gets send back to the http server
             */
            std::vector<boost::asio::const_buffer> to_buffers() const;

        private:
            /**
             * @brief The status of the reply.
             */
            int status_;

            /**
             * @brief An optional message to return additional information about the reply.
             */
            std::string message_;

            /**
             * @brief The paths of dangerous parameters.
             */
            std::vector<std::string> threats_;

            /**
             * @brief The json-encoded content of the reply.
             */
            std::string content_;
    };

    /**
     * @brief Reply pointer.
     */
    using reply_ptr = boost::shared_ptr<swd::reply>;
}

#endif /* REPLY_H */
