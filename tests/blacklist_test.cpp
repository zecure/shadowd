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

#include "blacklist.h"

BOOST_AUTO_TEST_SUITE(blacklist_test)

BOOST_AUTO_TEST_CASE(positive_blacklist_check_limit_by_profile) {
    swd::cache_ptr cache(new swd::cache(swd::database_ptr()));
    swd::blacklist blacklist(cache);

    swd::request_ptr request(new swd::request);
    request->set_caller("qux");
    swd::parameter_ptr parameter(new swd::parameter);
    parameter->set_path("bar");
    parameter->set_value("foo");
    request->add_parameter(parameter);

    swd::blacklist_filter_ptr filter(new swd::blacklist_filter);
    filter->set_impact(6);
    filter->set_regex("foo");

    swd::blacklist_filters filters;
    filters.push_back(filter);
    cache->set_blacklist_filters(filters);

    swd::blacklist_rules rules;
    cache->add_blacklist_rules(1, "qux", "bar", rules);

    swd::profile_ptr profile(new swd::profile);
    profile->set_id(1);
    profile->set_blacklist_threshold(5);
    request->set_profile(profile);

    blacklist.scan(request);
    BOOST_CHECK(parameter->get_blacklist_filters().size() == 1);
    BOOST_CHECK(parameter->is_threat() == true);
}

BOOST_AUTO_TEST_CASE(negative_blacklist_check_limit_by_profile) {
    swd::cache_ptr cache(new swd::cache(swd::database_ptr()));
    swd::blacklist blacklist(cache);

    swd::request_ptr request(new swd::request);
    request->set_caller("qux");
    swd::parameter_ptr parameter(new swd::parameter);
    parameter->set_path("boo");
    parameter->set_value("far");
    request->add_parameter(parameter);

    swd::blacklist_filter_ptr filter(new swd::blacklist_filter);
    filter->set_impact(6);
    filter->set_regex("foo");

    swd::blacklist_filters filters;
    filters.push_back(filter);
    cache->set_blacklist_filters(filters);

    swd::blacklist_rules rules;
    cache->add_blacklist_rules(1, "qux", "boo", rules);

    swd::profile_ptr profile(new swd::profile);
    profile->set_id(1);
    profile->set_blacklist_threshold(5);
    request->set_profile(profile);

    blacklist.scan(request);
    BOOST_CHECK(parameter->get_blacklist_filters().size() == 0);
    BOOST_CHECK(parameter->is_threat() == false);
}

BOOST_AUTO_TEST_CASE(negative_blacklist_check_no_limit_by_rule) {
    swd::cache_ptr cache(new swd::cache(swd::database_ptr()));
    swd::blacklist blacklist(cache);

    swd::request_ptr request(new swd::request);
    request->set_caller("qux");
    swd::parameter_ptr parameter(new swd::parameter);
    parameter->set_path("bar");
    parameter->set_value("foo");
    request->add_parameter(parameter);

    swd::blacklist_filter_ptr filter(new swd::blacklist_filter);
    filter->set_impact(6);
    filter->set_regex("foo");

    swd::blacklist_filters filters;
    filters.push_back(filter);
    cache->set_blacklist_filters(filters);

    swd::blacklist_rule_ptr rule(new swd::blacklist_rule);
    rule->set_threshold(-1);

    swd::blacklist_rules rules;
    rules.push_back(rule);
    cache->add_blacklist_rules(1, "qux", "bar", rules);

    swd::profile_ptr profile(new swd::profile);
    profile->set_id(1);
    profile->set_blacklist_threshold(5);
    request->set_profile(profile);

    blacklist.scan(request);
    BOOST_CHECK(parameter->get_blacklist_filters().size() == 1);
    BOOST_CHECK(parameter->is_threat() == false);
}

BOOST_AUTO_TEST_CASE(positive_blacklist_check_limit_by_rule) {
    swd::cache_ptr cache(new swd::cache(swd::database_ptr()));
    swd::blacklist blacklist(cache);

    swd::request_ptr request(new swd::request);
    request->set_caller("qux");
    swd::parameter_ptr parameter(new swd::parameter);
    parameter->set_path("bar");
    parameter->set_value("foo");
    request->add_parameter(parameter);

    swd::blacklist_filter_ptr filter(new swd::blacklist_filter);
    filter->set_impact(6);
    filter->set_regex("foo");

    swd::blacklist_filters filters;
    filters.push_back(filter);
    cache->set_blacklist_filters(filters);

    swd::blacklist_rule_ptr rule1(new swd::blacklist_rule);
    rule1->set_threshold(40);
    swd::blacklist_rule_ptr rule2(new swd::blacklist_rule);
    rule2->set_threshold(-1);
    swd::blacklist_rule_ptr rule3(new swd::blacklist_rule);
    rule3->set_threshold(5);

    swd::blacklist_rules rules;
    rules.push_back(rule1);
    rules.push_back(rule2);
    rules.push_back(rule3);
    cache->add_blacklist_rules(1, "qux", "bar", rules);

    swd::profile_ptr profile(new swd::profile);
    profile->set_id(1);
    profile->set_blacklist_threshold(50);
    request->set_profile(profile);

    blacklist.scan(request);
    BOOST_CHECK(parameter->get_blacklist_filters().size() == 1);
    BOOST_CHECK(parameter->is_threat() == true);
}

BOOST_AUTO_TEST_SUITE_END()
