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

#include "profile.h"

void swd::profile::set_server_ip(const std::string& server_ip) {
    server_ip_ = server_ip;
}

std::string swd::profile::get_server_ip() const {
    return server_ip_;
}

void swd::profile::set_id(const unsigned long long& id) {
    id_ = id;
}

unsigned long long swd::profile::get_id() const {
    return id_;
}

void swd::profile::set_mode(const unsigned int& mode) {
    mode_ = mode;
}

unsigned int swd::profile::get_mode() const {
    return mode_;
}

void swd::profile::set_whitelist_enabled(const bool& whitelist_enabled) {
    whitelist_enabled_ = whitelist_enabled;
}

bool swd::profile::is_whitelist_enabled() const {
    return whitelist_enabled_;
}

void swd::profile::set_blacklist_enabled(const bool& blacklist_enabled) {
    blacklist_enabled_ = blacklist_enabled;
}

bool swd::profile::is_blacklist_enabled() const {
    return blacklist_enabled_;
}

void swd::profile::set_integrity_enabled(const bool& integrity_enabled) {
    integrity_enabled_ = integrity_enabled;
}

bool swd::profile::is_integrity_enabled() const {
    return integrity_enabled_;
}

void swd::profile::set_flooding_enabled(const bool& flooding_enabled) {
    flooding_enabled_ = flooding_enabled;
}

bool swd::profile::is_flooding_enabled() const {
    return flooding_enabled_;
}

void swd::profile::set_key(const std::string& key) {
    key_ = key;
}

std::string swd::profile::get_key() const {
    return key_;
}

void swd::profile::set_blacklist_threshold(const int& blacklist_threshold) {
    blacklist_threshold_ = blacklist_threshold;
}

int swd::profile::get_blacklist_threshold() const {
    return blacklist_threshold_;
}

void swd::profile::set_cache_outdated(const bool& cache_outdated) {
    cache_outdated_ = cache_outdated;
}

bool swd::profile::is_cache_outdated() const {
    return cache_outdated_;
}
