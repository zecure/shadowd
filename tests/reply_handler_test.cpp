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

#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "reply_handler.h"

BOOST_AUTO_TEST_SUITE(reply_handler_test)

BOOST_AUTO_TEST_CASE(encode_normal) {
    swd::reply_ptr reply(new swd::reply);
    swd::reply_handler reply_handler(reply);

    reply->set_status(STATUS_OK);

    BOOST_CHECK(reply_handler.encode() == true);
    BOOST_CHECK(reply->get_content() == "{\"status\":1,\"threats\":[]}\n");
}

BOOST_AUTO_TEST_CASE(encode_attack) {
    swd::reply_ptr reply(new swd::reply);
    swd::reply_handler reply_handler(reply);

    std::vector<std::string> threats;
    threats.push_back("foo");
    threats.push_back("bar");
    reply->set_threats(threats);
    reply->set_status(STATUS_ATTACK);

    BOOST_CHECK(reply_handler.encode() == true);
    BOOST_CHECK(reply->get_content() == "{\"status\":5,\"threats\":[\"foo\",\"bar\"]}\n");
}

BOOST_AUTO_TEST_SUITE_END()
