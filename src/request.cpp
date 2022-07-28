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

#include <algorithm>
#include <sstream>

#include "request.h"

void swd::request::set_profile(const swd::profile_ptr& profile) {
    profile_ = profile;
}

swd::profile_ptr swd::request::get_profile() const {
    return profile_;
}

void swd::request::add_parameter(const swd::parameter_ptr& parameter) {
    parameters_.push_back(parameter);
}

void swd::request::add_parameter(const std::string& path,
 const std::string& value) {
    swd::parameter_ptr parameter(new swd::parameter);
    parameter->set_path(path);
    parameter->set_value(value);

    parameters_.push_back(parameter);
}

const swd::parameters& swd::request::get_parameters() const {
    return parameters_;
}

void swd::request::append_content(const char& input) {
    content_.push_back(input);
}

void swd::request::set_content(const std::string& content) {
    content_ = content;
}

std::string swd::request::get_content() const {
    return content_;
}

void swd::request::append_signature(const char& input) {
    signature_.push_back(input);
}

void swd::request::set_signature(const std::string& signature) {
    signature_ = signature;
}

std::string swd::request::get_signature() const {
    return signature_;
}

void swd::request::append_profile_id(const char& input) {
    profile_id_.push_back(input);
}

void swd::request::set_profile_id(const unsigned long long& profile_id) {
    std::stringstream ss;
    ss << profile_id;
    profile_id_ = ss.str();
}

unsigned long long swd::request::get_profile_id() const {
    return stoull(profile_id_);
}

void swd::request::set_client_ip(const std::string& client_ip) {
    client_ip_ = client_ip;
}

std::string swd::request::get_client_ip() const {
    return client_ip_;
}

void swd::request::set_caller(const std::string& caller) {
    caller_ = caller;
}

std::string swd::request::get_caller() const {
    return caller_;
}

void swd::request::set_resource(const std::string& resource) {
    resource_ = resource;
}

std::string swd::request::get_resource() const {
    return resource_;
}

void swd::request::add_integrity_rule(const swd::integrity_rule_ptr& rule) {
    integrity_rules_.push_back(rule);
}

const swd::integrity_rules& swd::request::get_integrity_rules() const {
    return integrity_rules_;
}

void swd::request::set_total_integrity_rules(const int& total_integrity_rules) {
    total_integrity_rules_ = total_integrity_rules;
}

int swd::request::get_total_integrity_rules() const {
    return total_integrity_rules_;
}

void swd::request::add_hash(const std::string& algorithm,
 const std::string& digest) {
    swd::hash_ptr hash(new swd::hash);
    hash->set_algorithm(algorithm);
    hash->set_digest(digest);

    hashes_[algorithm] = hash;
}

const swd::hashes& swd::request::get_hashes() const {
    return hashes_;
}

swd::hash_ptr swd::request::get_hash(const std::string& algorithm) /*const*/ {
    /* Necessary, otherwise element is created. */
    if (hashes_.find(algorithm) == hashes_.end()) {
        return swd::hash_ptr();
    }

    return hashes_[algorithm];
}

void swd::request::set_threat(const bool& threat) {
    threat_ = threat;
}

bool swd::request::is_threat() const {
    return threat_;
}

bool swd::request::has_threats() const {
    /* We only need to know if there is at least one threat. */
    return std::any_of(
            parameters_.begin(),
            parameters_.end(),
            [](auto parameter) {
                return parameter->is_threat();
            }
    );
}
