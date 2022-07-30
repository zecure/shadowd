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

#include <boost/date_time/posix_time/posix_time.hpp>
#include <utility>

#include "cache.h"
#include "log.h"
#include "database_exception.h"

swd::cache::cache(swd::database_ptr database) :
 database_(std::move(database)) {
}

void swd::cache::start() {
    worker_thread_ = boost::thread(
        boost::bind(&swd::cache::cleanup, this)
    );
}

void swd::cache::stop() {
    /* Stop on next loop. */
    stop_ = true;

    /* Interrupt and join thread to wait for end. */
    worker_thread_.interrupt();
    worker_thread_.join();
}

void swd::cache::cleanup() {
    while (!stop_) {
        {
            boost::unique_lock scoped_lock(blacklist_rules_mutex_);

            auto it_profile_id = blacklist_rules_.begin();
            while (it_profile_id != blacklist_rules_.end()) {
                auto it_caller = it_profile_id->second.begin();
                while (it_caller != it_profile_id->second.end()) {
                    auto it_blacklist_rule = it_caller->second.begin();
                    while (it_blacklist_rule != it_caller->second.end()) {
                        swd::cached_blacklist_rules_ptr rule(it_blacklist_rule->second);

                        if (rule->is_outdated()) {
                            it_blacklist_rule = it_caller->second.erase(it_blacklist_rule);
                        } else {
                            it_blacklist_rule++;
                        }
                    }

                    if (it_caller->second.empty()) {
                        it_caller = it_profile_id->second.erase(it_caller);
                    } else {
                        it_caller++;
                    }
                }

                if (it_profile_id->second.empty()) {
                    it_profile_id = blacklist_rules_.erase(it_profile_id);
                } else {
                    it_profile_id++;
                }
            }
        }

        {
            boost::unique_lock scoped_lock(whitelist_rules_mutex_);

            auto it_profile_id = whitelist_rules_.begin();
            while (it_profile_id != whitelist_rules_.end()) {
                auto it_caller = it_profile_id->second.begin();
                while (it_caller != it_profile_id->second.end()) {
                    auto it_whitelist_rule = it_caller->second.begin();
                    while (it_whitelist_rule != it_caller->second.end()) {
                        swd::cached_whitelist_rules_ptr rule(it_whitelist_rule->second);

                        if (rule->is_outdated()) {
                            it_whitelist_rule = it_caller->second.erase(it_whitelist_rule);
                        } else {
                            it_whitelist_rule++;
                        }
                    }

                    if (it_caller->second.empty()) {
                        it_caller = it_profile_id->second.erase(it_caller);
                    } else {
                        it_caller++;
                    }
                }

                if (it_profile_id->second.empty()) {
                    it_profile_id = whitelist_rules_.erase(it_profile_id);
                } else {
                    it_profile_id++;
                }
            }
        }

        {
            boost::unique_lock scoped_lock(integrity_rules_mutex_);

            auto it_profile_id = integrity_rules_.begin();
            while (it_profile_id != integrity_rules_.end()) {
                auto it_integrity_rule = it_profile_id->second.begin();
                while (it_integrity_rule != it_profile_id->second.end()) {
                    swd::cached_integrity_rules_ptr rule(it_integrity_rule->second);

                    if (rule->is_outdated()) {
                        it_integrity_rule = it_profile_id->second.erase(it_integrity_rule);
                    } else {
                        it_integrity_rule++;
                    }
                }

                if (it_profile_id->second.empty()) {
                    it_profile_id = integrity_rules_.erase(it_profile_id);
                } else {
                    it_profile_id++;
                }
            }
        }

        /* Sleep most of the time for performance. */
        try {
            boost::this_thread::sleep(boost::posix_time::seconds(60));
        } catch (boost::thread_interrupted) {}
    }
}

void swd::cache::reset_profile(unsigned long long profile_id) {
    swd::log::i()->send(swd::notice, "Resetting the cache");

    try {
        database_->set_cache_outdated(profile_id, false);
    } catch (const swd::exceptions::database_exception& e) {
        swd::log::i()->send(swd::uncritical_error, e.get_message());
    }

    {
        boost::unique_lock scoped_lock(blacklist_rules_mutex_);
        blacklist_rules_[profile_id].clear();
    }

    {
        boost::unique_lock scoped_lock(whitelist_rules_mutex_);
        whitelist_rules_[profile_id].clear();
    }

    {
        boost::unique_lock scoped_lock(integrity_rules_mutex_);
        integrity_rules_[profile_id].clear();
    }
}

void swd::cache::reset_all() {
    swd::log::i()->send(swd::notice, "Resetting the cache");

    try {
        database_->set_cache_outdated(false);
    } catch (const swd::exceptions::database_exception& e) {
        swd::log::i()->send(swd::uncritical_error, e.get_message());
    }

    {
        boost::unique_lock scoped_lock(blacklist_filters_mutex_);
        blacklist_filters_.clear();
    }

    {
        boost::unique_lock scoped_lock(blacklist_rules_mutex_);
        blacklist_rules_.clear();
    }

    {
        boost::unique_lock scoped_lock(whitelist_rules_mutex_);
        whitelist_rules_.clear();
    }

    {
        boost::unique_lock scoped_lock(integrity_rules_mutex_);
        integrity_rules_.clear();
    }
}

void swd::cache::set_blacklist_filters(const swd::blacklist_filters&
 blacklist_filters) {
    boost::unique_lock scoped_lock(blacklist_filters_mutex_);

    blacklist_filters_ = blacklist_filters;
}

swd::blacklist_filters swd::cache::get_blacklist_filters() {
    boost::unique_lock scoped_lock(blacklist_filters_mutex_);

    if (!blacklist_filters_.empty()) {
        return blacklist_filters_;
    }

    blacklist_filters_ = database_->get_blacklist_filters();

    return blacklist_filters_;
}

void swd::cache::add_blacklist_rules(const unsigned long long& profile_id,
 const std::string& caller, const std::string& path,
 const swd::blacklist_rules& blacklist_rules) {
    boost::unique_lock scoped_lock(blacklist_rules_mutex_);

    swd::cached_blacklist_rules_ptr cached_blacklist_rules(
        new swd::cached_blacklist_rules(blacklist_rules)
    );

    blacklist_rules_[profile_id][caller][path] = cached_blacklist_rules;
}


swd::blacklist_rules swd::cache::get_blacklist_rules(const unsigned long long& profile_id,
 const std::string& caller, const std::string& path) {
    boost::unique_lock scoped_lock(blacklist_rules_mutex_);

    if (blacklist_rules_[profile_id][caller].find(path) !=
     blacklist_rules_[profile_id][caller].end()) {
        return blacklist_rules_[profile_id][caller][path]->get_value();
    }

    swd::blacklist_rules blacklist_rules =
     database_->get_blacklist_rules(profile_id, caller, path);

    swd::cached_blacklist_rules_ptr cached_blacklist_rules(
        new swd::cached_blacklist_rules(blacklist_rules)
    );

    blacklist_rules_[profile_id][caller][path] = cached_blacklist_rules;

    return blacklist_rules;
}

void swd::cache::add_whitelist_rules(const unsigned long long& profile_id,
 const std::string& caller, const std::string& path,
 const swd::whitelist_rules& whitelist_rules) {
    boost::unique_lock scoped_lock(whitelist_rules_mutex_);

    swd::cached_whitelist_rules_ptr cached_whitelist_rules(
        new swd::cached_whitelist_rules(whitelist_rules)
    );

    whitelist_rules_[profile_id][caller][path] = cached_whitelist_rules;
}

swd::whitelist_rules swd::cache::get_whitelist_rules(const unsigned long long& profile_id,
 const std::string& caller, const std::string& path) {
    boost::unique_lock scoped_lock(whitelist_rules_mutex_);

    if (whitelist_rules_[profile_id][caller].find(path) !=
     whitelist_rules_[profile_id][caller].end()) {
        return whitelist_rules_[profile_id][caller][path]->get_value();
    }

    swd::whitelist_rules whitelist_rules =
     database_->get_whitelist_rules(profile_id, caller, path);

    swd::cached_whitelist_rules_ptr cached_whitelist_rules(
        new swd::cached_whitelist_rules(whitelist_rules)
    );

    whitelist_rules_[profile_id][caller][path] = cached_whitelist_rules;

    return whitelist_rules;
}

void swd::cache::add_integrity_rules(const unsigned long long& profile_id,
 const std::string& caller, const swd::integrity_rules& integrity_rules) {
    boost::unique_lock scoped_lock(integrity_rules_mutex_);

    swd::cached_integrity_rules_ptr cached_integrity_rules(
        new swd::cached_integrity_rules(integrity_rules)
    );

    integrity_rules_[profile_id][caller] = cached_integrity_rules;
}

swd::integrity_rules swd::cache::get_integrity_rules(const unsigned long long& profile_id,
 const std::string& caller) {
    boost::unique_lock scoped_lock(integrity_rules_mutex_);

    if (integrity_rules_[profile_id].find(caller) !=
     integrity_rules_[profile_id].end()) {
        return integrity_rules_[profile_id][caller]->get_value();
    }

    swd::integrity_rules integrity_rules =
     database_->get_integrity_rules(profile_id, caller);

    swd::cached_integrity_rules_ptr cached_integrity_rules(
        new swd::cached_integrity_rules(integrity_rules)
    );

    integrity_rules_[profile_id][caller] = cached_integrity_rules;

    return integrity_rules;
}
