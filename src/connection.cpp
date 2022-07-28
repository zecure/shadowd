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

#include <utility>

#include "connection.h"
#include "profile.h"
#include "request_handler.h"
#include "reply_handler.h"
#include "config.h"
#include "log.h"
#include "database_exception.h"
#include "connection_exception.h"

swd::connection::connection(boost::asio::io_service& io_service,
 swd::context& context, bool ssl, swd::storage_ptr storage,
 swd::database_ptr database, swd::cache_ptr cache) :
 strand_(io_service),
 socket_(io_service),
 ssl_socket_(io_service, context),
 ssl_(ssl),
 storage_(std::move(storage)),
 database_(std::move(database)),
 cache_(std::move(cache)) {
}

swd::socket& swd::connection::socket() {
    return socket_;
}

swd::ssl_socket::lowest_layer_type& swd::connection::ssl_socket() {
    return ssl_socket_.lowest_layer();
}

void swd::connection::start() {
    /* Save the ip of the httpd server in the request object. */
    boost::asio::ip::tcp::endpoint remote_endpoint;

    if (ssl_) {
        remote_endpoint = ssl_socket_.lowest_layer().remote_endpoint();
    } else {
        remote_endpoint = socket_.remote_endpoint();
    }

    remote_address_ = remote_endpoint.address();

    if (ssl_) {
        swd::log::i()->send(swd::notice, "Starting new ssl connection with "
         + remote_address_.to_string());

        /**
         * If this is a SSL connection we have to do a handshake before we can
         * start reading.
         */
        ssl_socket_.async_handshake(
            boost::asio::ssl::stream_base::server,
            strand_.wrap(
                boost::bind(
                    &connection::start_read,
                    shared_from_this(),
                    boost::asio::placeholders::error
                )
            )
        );
    } else {
        swd::log::i()->send(swd::notice, "Starting new connection with "
         + remote_address_.to_string());

        /* No SSL, directly start reading the input. */
        start_read();
    }
}

void swd::connection::start_read() {
    if (ssl_) {
        ssl_socket_.async_read_some(
            boost::asio::buffer(buffer_),
            strand_.wrap(
                boost::bind(
                    &connection::handle_read,
                    shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred
                )
            )
        );
    } else {
        socket_.async_read_some(
            boost::asio::buffer(buffer_),
            strand_.wrap(
                boost::bind(
                    &connection::handle_read,
                    shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred
                )
            )
        );
    }
}

void swd::connection::start_read(const boost::system::error_code& e) {
    if (e) {
        return;
    }

    start_read();
}

void swd::connection::handle_read(const boost::system::error_code& e,
 std::size_t bytes_transferred) {
    /**
     * If an error occurs then no new asynchronous operations are started. This
     * means that all shared_ptr references to the connection object will disappear
     * and the object will be destroyed automatically after this handler returns.
     * The connection class's destructor closes the socket.
     */
    if (e) {
        return;
    }

    /**
     * Since there was no error we can start parsing the input now. The parser
     * fills the object request_ with data.
     */
    boost::tribool result;
    boost::tie(result, boost::tuples::ignore) =
        request_parser_.parse(
            request_,
            buffer_.data(),
            buffer_.data() + bytes_transferred
        );

    /**
     * If result is true the complete request is parsed. If it is false there was
     * an error. If it is indeterminate then the parsing is not complete yet and
     * the program will read more input and append it to the old request_ object.
     */
    if (indeterminate(result)) {
        /* Not finished yet with this request, start reading again. */
        this->start_read();

        /* And don't process the input yet. */
        return;
    }

    /* The handler used to process the reply. */
    swd::reply_handler reply_handler(reply_);

    try {
        if (!result) {
            throw swd::exceptions::connection_exception(
                STATUS_BAD_REQUEST,
                "Bad request from " + remote_address_.to_string()
            );
        }

        /* Try to add a profile for the request. */
        try {
            swd::profile_ptr profile = database_->get_profile(
                remote_address_.to_string(),
                request_->get_profile_id()
            );

            request_->set_profile(profile);
        } catch (const swd::exceptions::database_exception& e) {
            throw swd::exceptions::connection_exception(
                STATUS_BAD_REQUEST,
                "Database error when fetching profile: " + e.get_message()
            );
        }

        /* The handler used to process the incoming request. */
        swd::request_handler request_handler(request_, cache_, storage_);

        /* Only continue processing the reply if it is signed correctly. */
        if (!request_handler.valid_signature()) {
            throw swd::exceptions::connection_exception(
                STATUS_BAD_SIGNATURE,
                "Bad signature from " + remote_address_.to_string()
            );
        }

        /**
         * Before the request can be processed the input has to be transfered
         * from the encoded json string to a swd::parameters list.
         */
        if (!request_handler.decode()) {
            throw swd::exceptions::connection_exception(
                STATUS_BAD_JSON,
                "Bad json from " + remote_address_.to_string()
            );
        }

        /* Check profile for outdated cache. */
        swd::profile_ptr profile = request_->get_profile();

        if (profile->is_cache_outdated()) {
            cache_->reset_profile(profile->get_id());
        }

        /* Process the request. */
        std::vector<std::string> threats;

        try {
            swd::parameters parameters = request_->get_parameters();

            /** Check security limitations first. */
            int max_params = swd::config::i()->get<int>("max-parameters");

            if ((max_params > -1) && (parameters.size() > max_params)) {
                throw swd::exceptions::connection_exception(
                    STATUS_BAD_REQUEST,
                    "Too many parameters"
                );
            }

            int max_length_path = swd::config::i()->get<int>("max-length-path");
            int max_length_value = swd::config::i()->get<int>("max-length-value");

            if ((max_length_path > -1) || (max_length_value > -1)) {
                for (const auto& parameter: parameters) {
                    if ((max_length_path > -1) && (parameter->get_path().length() > max_length_path)) {
                        throw swd::exceptions::connection_exception(
                            STATUS_BAD_REQUEST,
                            "Too long parameter path"
                        );
                    }

                    if ((max_length_value > -1) && (parameter->get_value().length() > max_length_value)) {
                        throw swd::exceptions::connection_exception(
                            STATUS_BAD_REQUEST,
                            "Too long parameter value"
                        );
                    }
                }
            }

            if (profile->is_flooding_enabled()) {
                if (database_->is_flooding(request_->get_client_ip(), profile->get_id())) {
                    throw swd::exceptions::connection_exception(
                        STATUS_BAD_REQUEST,
                        "Too many requests"
                    );
                }
            }

            /* Time to analyze the request. */
            request_handler.process();
        } catch (const swd::exceptions::database_exception& e) {
            /**
             * Problems with the database result in a bad request. If protection
             * is enabled access to the site will not be granted.
             */
            throw swd::exceptions::connection_exception(
                STATUS_BAD_REQUEST,
                "Database error: " + e.get_message()
            );
        }

        if (profile->get_mode() == MODE_ACTIVE) {
            if (request_->is_threat()) {
                reply_->set_status(STATUS_CRITICAL_ATTACK);
            } else if (request_->has_threats()) {
                reply_->set_threats(request_handler.get_threats());
                reply_->set_status(STATUS_ATTACK);
            } else {
                reply_->set_status(STATUS_OK);
            }
        } else {
            reply_->set_status(STATUS_OK);
        }
    } catch (const swd::exceptions::connection_exception& e) {
        swd::log::i()->send(swd::warning, e.get_message());

        if (!request_->get_profile() || request_->get_profile()->get_mode() == MODE_ACTIVE) {
            reply_->set_status(e.get_code());
            reply_->set_message(e.get_message());
        } else {
            reply_->set_status(STATUS_OK);
        }
    }

    /* Encode the reply. */
    reply_handler.encode();

    /* Send the answer to the client. */
    if (ssl_) {
        boost::asio::async_write(
            ssl_socket_,
            reply_->to_buffers(),
            strand_.wrap(
                boost::bind(
                    &connection::handle_write,
                    shared_from_this(),
                    boost::asio::placeholders::error
                )
            )
        );
    } else {
        boost::asio::async_write(
            socket_,
            reply_->to_buffers(),
            strand_.wrap(
                boost::bind(
                    &connection::handle_write,
                    shared_from_this(),
                    boost::asio::placeholders::error
                )
            )
        );
    }
}

void swd::connection::handle_write(const boost::system::error_code& e) {
    if (!e) {
        boost::system::error_code ignored_ec;

        /* Initiate graceful connection closure. */
        if (ssl_) {
            ssl_socket_.shutdown(ignored_ec);
        } else {
            socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored_ec);
        }
    }

    /**
     * No new asynchronous operations are started. This means that all shared_ptr
     * references to the connection object will disappear and the object will be
     * destroyed automatically after this handler returns. The connection class's
     * destructor closes the socket.
     */
}
