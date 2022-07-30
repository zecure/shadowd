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

#include "request_handler.h"

BOOST_AUTO_TEST_SUITE(request_handler_test)

BOOST_AUTO_TEST_CASE(valid_signature) {
    swd::request_ptr request(new swd::request);
    swd::request_handler request_handler(request, swd::cache_ptr(), swd::storage_ptr());
    swd::profile_ptr profile(new swd::profile);

    profile->set_key("foo");
    request->set_profile(profile);
    request->set_signature("f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317");
    request->set_content("bar");

    BOOST_CHECK(request_handler.valid_signature() == true);
}

BOOST_AUTO_TEST_CASE(invalid_signature) {
    swd::request_ptr request(new swd::request);
    swd::request_handler request_handler(request, swd::cache_ptr(), swd::storage_ptr());
    swd::profile_ptr profile(new swd::profile);

    profile->set_key("qux");
    request->set_profile(profile);
    request->set_content("bar");

    BOOST_CHECK(request_handler.valid_signature() == false);

    request->set_signature("f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317");
    BOOST_CHECK(request_handler.valid_signature() == false);
}

BOOST_AUTO_TEST_CASE(valid_decode) {
    swd::request_ptr request(new swd::request);
    swd::request_handler request_handler(request, swd::cache_ptr(), swd::storage_ptr());

    request->set_content("{\"version\":\"2.0.0-php\",\"client_ip\":\"127.0.0.1\",\"caller\":"
     "\"foo\",\"resource\":\"\\/bar.php\",\"input\":{\"foo\":\"bar\"},\"hashes\":{\"foo\":\"bar\"}}");
    BOOST_CHECK(request_handler.decode() == true);
}

BOOST_AUTO_TEST_CASE(invalid_decode) {
    swd::request_ptr request(new swd::request);
    swd::request_handler request_handler(request, swd::cache_ptr(), swd::storage_ptr());

    BOOST_CHECK(request_handler.decode() == false);

    request->set_content("{}");
    BOOST_CHECK(request_handler.decode() == false);

    request->set_content("[]");
    BOOST_CHECK(request_handler.decode() == false);

    request->set_content("{\"version\":{},\"client_ip\":{},\"caller\":{},\"resource\":{},"
     "\"input\":[],\"hashes\":[]}");
    BOOST_CHECK(request_handler.decode() == false);
}

BOOST_AUTO_TEST_CASE(nullbyte_decode) {
    swd::request_ptr request(new swd::request);
    swd::request_handler request_handler(request, swd::cache_ptr(), swd::storage_ptr());

    request->set_content("{\"version\":\"\",\"client_ip\":\"\",\"caller\":\"\",\"resource\":"
     "\"foo\\u0000bar\",\"input\":{},\"hashes\":{}}");
    BOOST_CHECK(request_handler.decode() == true);

    std::stringstream expected;
    expected << "foo" << '\0' << "bar";
    BOOST_CHECK(request->get_resource() == expected.str());
}

BOOST_AUTO_TEST_CASE(get_threats) {
    swd::request_ptr request(new swd::request);
    swd::request_handler request_handler(request, swd::cache_ptr(), swd::storage_ptr());
    swd::parameter_ptr parameter_ok(new swd::parameter);
    swd::parameter_ptr parameter_threat(new swd::parameter);

    parameter_ok->set_path("foo");
    parameter_ok->set_value("bar");
    request->add_parameter(parameter_ok);
    parameter_threat->set_path("faa");
    parameter_threat->set_value("bor");
    parameter_threat->set_threat(true);
    request->add_parameter(parameter_threat);

    std::vector<std::string> threats = request_handler.get_threats();
    BOOST_CHECK(threats.size() == 1);
    BOOST_CHECK(threats[0] == "faa");
}

BOOST_AUTO_TEST_SUITE_END()
