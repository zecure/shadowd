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

#ifndef REQUEST_HANDLER_H
#define REQUEST_HANDLER_H

#include <vector>
#include <string>

#include "request.h"
#include "cache.h"
#include "storage.h"

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
             * @param cache The pointer to the cache object
             * @param storage The pointer to the storage object
             */
            request_handler(swd::request_ptr request,
             swd::cache_ptr cache, swd::storage_ptr storage);

            /**
             * @brief Check if the signature of the request is valid.
             *
             * @return Status of hmac check
             */
            bool valid_signature() const;

            /**
             * @brief Decode the json string.
             *
             * @return Status of decoding
             */
            bool decode() const;

            /**
             * @brief Start the real processing of the request.
             */
            void process() const;

            /**
             * @brief Get the threats of the processing.
             *
             * @return A list of all paths that should be protected
             */
            std::vector<std::string> get_threats() const;

        private:
            /**
             * @brief The pointer to the request object.
             */
            swd::request_ptr request_;

            /**
             * @brief The pointer to the cache object.
             */
            swd::cache_ptr cache_;

            /**
             * @brief The pointer to the storage object.
             */
            swd::storage_ptr storage_;
    };
}

#endif /* REQUEST_HANDLER_H */
