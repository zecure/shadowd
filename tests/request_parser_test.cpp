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
#include <boost/array.hpp>
#include <sstream>

#include "request_parser.h"

BOOST_AUTO_TEST_SUITE(request_parser_test)

BOOST_AUTO_TEST_CASE(valid_parse) {
    swd::request_ptr request(new swd::request);

    /* Prepare the input and copy it into a boost char array. */
    int profile_id = 13;
    std::string signature = "147933218aaabc0b8b10a2b3a5c34684c8d94341bcf10a4736dc7270f7741851";
    std::string content = "{\"foo\": \"1.0\", \"bar\": \"baz!\", \"qux\": [23, 42]}";

    std::stringstream input_stream;
    input_stream << profile_id << "\n" << signature << "\n" << content << "\n";
    std::string input = input_stream.str();

    boost::array<char, 256> buffer;
    std::copy(input.begin(), input.end(), buffer.data());

    /* Parse the char array and save it into a request object. */
    swd::request_parser parser;

    boost::tribool result;
    boost::tie(result, boost::tuples::ignore) =
        parser.parse(
            request,
            buffer.data(),
            buffer.data() + input.length()
        );

    /* First we check the status code of parse. */
    BOOST_CHECK(indeterminate(result) == false);
    BOOST_CHECK((bool)result == true);

    /* The parsed version should equal the initial values again. */
    BOOST_CHECK(request->get_profile_id() == profile_id);
    BOOST_CHECK(request->get_signature() == signature);
    BOOST_CHECK(request->get_content() == content);
}

BOOST_AUTO_TEST_CASE(incomplete_parse) {
    swd::request_ptr request(new swd::request);

    /* Prepare the input and copy it into a boost char array. */
    std::string input = "1\na\na";

    boost::array<char, 256> buffer;
    std::copy(input.begin(), input.end(), buffer.data());

    /* Parse the char array and save it into a request object. */
    swd::request_parser parser;

    boost::tribool result;
    boost::tie(result, boost::tuples::ignore) =
        parser.parse(
            request,
            buffer.data(),
            buffer.data() + input.length()
        );

    /* Check the status code of parse. */
    BOOST_CHECK(indeterminate(result) == true);
}

BOOST_AUTO_TEST_CASE(invalid_parse_id) {
    swd::request_ptr request(new swd::request);

    /* Prepare the input and copy it into a boost char array. */
    std::string input = "!\na\na\n";

    boost::array<char, 256> buffer;
    std::copy(input.begin(), input.end(), buffer.data());

    /* Parse the char array and save it into a request object. */
    swd::request_parser parser;

    boost::tribool result;
    boost::tie(result, boost::tuples::ignore) =
        parser.parse(
            request,
            buffer.data(),
            buffer.data() + input.length()
        );

    /* Check the status code of parse. */
    BOOST_CHECK(indeterminate(result) == false);
    BOOST_CHECK((bool)result == false);
}

BOOST_AUTO_TEST_CASE(invalid_parse_hmac) {
    swd::request_ptr request(new swd::request);

    /* Prepare the input and copy it into a boost char array. */
    std::string input = "1\n!\na\n";

    boost::array<char, 256> buffer;
    std::copy(input.begin(), input.end(), buffer.data());

    /* Parse the char array and save it into a request object. */
    swd::request_parser parser;

    boost::tribool result;
    boost::tie(result, boost::tuples::ignore) =
        parser.parse(
            request,
            buffer.data(),
            buffer.data() + input.length()
        );

    /* Check the status code of parse. */
    BOOST_CHECK(indeterminate(result) == false);
    BOOST_CHECK((bool)result == false);
}

BOOST_AUTO_TEST_SUITE_END()
