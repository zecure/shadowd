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

#ifndef SERVER_H
#define SERVER_H

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>

#include "connection.h"
#include "storage.h"
#include "cache.h"

namespace swd {
    /**
     * @brief Initializes the network server and adds threads to a thread pool.
     */
    class server :
     private boost::noncopyable {
        public:
            /**
             * @brief Construct an object and connect the attributes.
             *
             * @param storage The pointer to the storage object
             * @param database The pointer to the database object
             * @param cache The pointer to the cache object
             */
            server(swd::storage_ptr storage,
             swd::database_ptr database, swd::cache_ptr cache);

            /**
             * @brief Initialize the server.
             *
             * This method opens the tcp port. It is called before root
             * privileges are dropped, so every free port can be used.
             */
            void init();

            /**
             * @brief Add threads to the thread pool and start accepting connections.
             *
             * @param thread_pool_size The number of threads that should be
             *  added to the thread pool
             */
            void start(std::size_t thread_pool_size);

        private:
            /**
             * @brief Initiate an asynchronous accept operation.
             */
            void start_accept();

            /**
             * @brief Handle completion of an asynchronous accept operation.
             */
            void handle_accept(const boost::system::error_code& e);

            /**
             * @brief Handle a request to stop the server.
             */
            void handle_stop();

            /**
             * @brief Handle a request to reload internal data.
             */
            void handle_reload();

            /**
             * @brief The io_service used to perform asynchronous operations.
             */
            boost::asio::io_service io_service_;

            /**
             * @brief The signal_set is used to register for process termination
             *  notifications.
             */
            boost::asio::signal_set signals_stop_;

            /**
             * @brief The signal_set is used to register for process reload
             *  notifications.
             */
            boost::asio::signal_set signals_reload_;

            /**
             * @brief Acceptor used to listen for incoming connections.
             */
            swd::acceptor acceptor_;

            /**
             * @brief The ssl context that contains the settings if ssl is activated.
             */
            swd::context context_;

            /**
             * @brief The next connection to be accepted.
             */
            swd::connection_ptr new_connection_;

            /**
             * @brief The pointer to the storage object.
             */
            swd::storage_ptr storage_;

            /**
             * @brief The pointer to the database object.
             */
            swd::database_ptr database_;

            /**
             * @brief The pointer to the cache object.
             */
            swd::cache_ptr cache_;
    };
}

#endif /* SERVER_H */
