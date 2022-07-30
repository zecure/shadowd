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

#ifndef STORAGE_H
#define STORAGE_H

#include <queue>
#include <boost/thread.hpp>

#include "request.h"
#include "database.h"

namespace swd {
    /**
     * @brief Manages the storage of a request.
     */
    class storage {
        public:
            /**
             * @brief Initialize the storage object.
             *
             * @param database The pointer to the database object
             */
            storage(swd::database_ptr database);

            /**
             * @brief Start insert thread.
             */
            void start();

            /**
             * @brief Gracefully stop process_next.
             */
            void stop();

            /**
             * @brief Add request to insert queue.
             *
             * @param request The pointer to the request object
             */
            void add(const swd::request_ptr& request);

        private:
            /**
             * @brief Process the next request in the queue.
             */
            void process_next();

            /**
             * @brief Save a complete request in the database.
             *
             * @param request The pointer to the request object
             */
            void save(const swd::request_ptr& request);

            /**
             * @brief Request queue for performance improvements.
             */
            std::queue<swd::request_ptr> queue_;

            /**
             * @brief Mutex for queue to avoid race conditions.
             */
            boost::mutex queue_mutex_;

            /**
             * @brief Thread that constantly checks queue for new entries.
             */
            boost::thread worker_thread_;

            /**
             * @brief Switch to exit process_next loop.
             */
            bool stop_ = false;

            /**
             * @brief Notify consumer threads on new requests in the queue.
             */
            boost::condition_variable cond_;

            /**
             * @brief Mutex required for condition variable.
             */
            boost::mutex consumer_mutex_;

            /**
             * @brief The pointer to the database object.
             */
            swd::database_ptr database_;
    };

    /**
     * @brief Storage pointer.
     */
    using storage_ptr = boost::shared_ptr<swd::storage>;
}

#endif /* STORAGE_H */
