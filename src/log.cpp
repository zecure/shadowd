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

#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <ostream>

#include "log.h"
#include "config.h"

void swd::log::open_file(const std::string& file) {
    /* Use mutex to avoid race conditions. */
    boost::unique_lock scoped_lock(mutex_);

    /* Set the file. */
    file_ = file;
}

void swd::log::send(const swd::log_level& level, const std::string& message) {
    /* Skip warning & notice if verbose is not enabled. */
    if (!swd::config::i()->defined("verbose")) {
        if ((level == warning) || (level == notice)) {
            return;
        }
    }

    /* Build an informative output line. */
    std::stringstream line;

    line << this->get_current_time() << "\t";

    switch (level) {
        case critical_error:
            line << "Critical error";
            break;
        case uncritical_error:
            line << "Uncritical error";
            break;
        case warning:
            line << "Warning";
            break;
        case notice:
            line << "Notice";
            break;
    }

    line << "\t" << message << "\n";

    /* Use mutex to avoid race conditions. */
    boost::unique_lock scoped_lock(mutex_);

    /* Write the final line into a log file or stderr. */
    if (!file_.empty()) {
        std::ofstream out_file(file_.c_str(), std::ios_base::app);

        if (!out_file.is_open()) {
            return;
        }

        out_file << line.str();
        out_file.close();
    } else {
        std::cerr << line.str();
    }
}

std::string swd::log::get_current_time() const {
    auto now = std::time(nullptr);
    struct tm local_time{};
    localtime_r(&now, &local_time);

    std::ostringstream oss;
    oss << std::put_time(&local_time, "%Y-%m-%d %X");

    return oss.str();
}
