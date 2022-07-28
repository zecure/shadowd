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

#include "request.h"

BOOST_AUTO_TEST_SUITE(request_test)

BOOST_AUTO_TEST_CASE(has_threats) {
    swd::request_ptr request(new swd::request);
    swd::parameter_ptr parameter_ok(new swd::parameter);
    swd::parameter_ptr parameter_threat(new swd::parameter);

    parameter_ok->set_path("foo");
    parameter_ok->set_value("bar");
    request->add_parameter(parameter_ok);
    BOOST_CHECK(request->has_threats() == false);

    parameter_threat->set_path("faa");
    parameter_threat->set_value("bor");
    parameter_threat->set_threat(true);
    request->add_parameter(parameter_threat);
    BOOST_CHECK(request->has_threats() == true);
}

BOOST_AUTO_TEST_SUITE_END()
