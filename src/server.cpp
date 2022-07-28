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

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/thread.hpp>
#include <string>
#include <utility>

#include "server.h"
#include "config.h"
#include "log.h"
#include "shared.h"
#include "core_exception.h"

swd::server::server(swd::storage_ptr storage,
 swd::database_ptr database, swd::cache_ptr cache) :
 signals_stop_(io_service_),
 signals_reload_(io_service_),
 acceptor_(io_service_),
 context_(boost::asio::ssl::context::sslv23),
 storage_(std::move(storage)),
 database_(std::move(database)),
 cache_(std::move(cache)) {
    /**
     * Register to handle the signals that indicate when the server should exit.
     * It is safe to register for the same signal multiple times in a program,
     * provided all registration for the specified signal is made through asio.
     */
    signals_stop_.add(SIGINT);
    signals_stop_.add(SIGTERM);
#if defined(SIGQUIT)
    signals_stop_.add(SIGQUIT);
#endif /* defined(SIGQUIT) */

    signals_stop_.async_wait(
        boost::bind(&swd::server::handle_stop, this)
    );

    /* Do the same for reload signals. */
    signals_reload_.add(SIGHUP);

    signals_reload_.async_wait(
        boost::bind(&swd::server::handle_reload, this)
    );
}

void swd::server::init() {
    /**
     * We try to open the tcp port. If asio throws an error one of the core
     * components doesn't work and there is no need to continue in that case.
     */
    try {
        if (swd::config::i()->defined("ssl")) {
            context_.set_options(
                boost::asio::ssl::context::default_workarounds
                | boost::asio::ssl::context::no_sslv2
                | boost::asio::ssl::context::single_dh_use
            );

            context_.use_certificate_chain_file(
                swd::config::i()->get<std::string>("ssl-cert")
            );

            context_.use_private_key_file(
                swd::config::i()->get<std::string>("ssl-key"),
                boost::asio::ssl::context::pem
            );

            context_.use_tmp_dh_file(
                swd::config::i()->get<std::string>("ssl-dh")
            );
        }

        /* Open the acceptor with the option to reuse the address (i.e. SO_REUSEADDR). */
        boost::asio::ip::tcp::resolver resolver(io_service_);

        boost::asio::ip::tcp::resolver::query query(
            swd::config::i()->get<std::string>("address"),
            swd::config::i()->get<std::string>("port")
        );

        boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve(query);

        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen();
    } catch (const boost::system::system_error &e) {
        throw swd::exceptions::core_exception(e.what());
    }

    start_accept();
}

void swd::server::start(std::size_t thread_pool_size) {
    /**
     * In some cases the compiler can't determine which overload of run was intended
     * at the bind, resulting in a compilation error.
     *
     * This solution for the problem is based on the answer from Dave S at:
     * https://stackoverflow.com/questions/13476201/difference-between-boostthread-and-stdthread
     */
    using signature_type = std::size_t (boost::asio::io_service::*)();
    signature_type run_ptr = &boost::asio::io_service::run;

    /* Create a pool of threads to run all of the io_services. */
    std::vector<boost::shared_ptr<boost::thread> > threads;

    for (std::size_t i = 0; i < thread_pool_size; ++i) {
        boost::shared_ptr<boost::thread> thread(
            new boost::thread(
                boost::bind(run_ptr, &io_service_)
            )
        );

        threads.push_back(thread);
    }

    /* Wait for all threads in the pool to exit. */
    for (const auto& thread: threads) {
        thread->join();
    }
}

void swd::server::start_accept() {
    bool ssl = swd::config::i()->defined("ssl");

    new_connection_.reset(
        new swd::connection(
            io_service_,
            context_,
            ssl,
            storage_,
            database_,
            cache_
        )
    );

    acceptor_.async_accept(
        (ssl ? new_connection_->ssl_socket() : new_connection_->socket()),
        boost::bind(
            &swd::server::handle_accept,
            this,
            boost::asio::placeholders::error
        )
    );
}

void swd::server::handle_accept(const boost::system::error_code& e) {
    /**
     * Try to process the connection, but do not stop the complete server if
     * something from asio doesn't work out.
     */
    try {
        if (!e) {
            new_connection_->start();
        }
    } catch (const boost::system::system_error &e) {
        swd::log::i()->send(swd::uncritical_error, e.what());
    }

    /* Reset the connection and wait for the next client. */
    start_accept();
}

void swd::server::handle_stop() {
    swd::log::i()->send(swd::notice, "Received a stop signal");

    /* Stop the threads of asio. */
    io_service_.stop();

    /* Stop the storage thread. */
    storage_->stop();

    /* Stop the cache thread. */
    cache_->stop();
}

void swd::server::handle_reload() {
    swd::log::i()->send(swd::notice, "Received a reload signal");

    /* Reset the cache by deleting all elements. */
    cache_->reset_all();
}
