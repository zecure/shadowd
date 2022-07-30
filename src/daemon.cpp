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

#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <iostream>
#include <fstream>

#include "daemon.h"
#include "shared.h"
#include "core_exception.h"

void swd::daemon::set_user(const std::string& user) const {
    struct passwd *u = getpwnam(user.c_str());

    if (!u) {
        throw swd::exceptions::core_exception("getpwnam() failed");
    }

    if (setuid(u->pw_uid) == -1) {
        throw swd::exceptions::core_exception("setuid() failed");
    }
}

void swd::daemon::set_group(const std::string& group) const {
    if (setgroups(0, nullptr) == -1) {
        throw swd::exceptions::core_exception("setgroups() failed");
    }

    struct group *g = getgrnam(group.c_str());

    if (!g) {
        throw swd::exceptions::core_exception("getgrnam() failed");
    }

    if (setgid(g->gr_gid) == -1) {
        throw swd::exceptions::core_exception("setgid() failed");
    }
}

void swd::daemon::write_pid(const std::string& file) const {
    std::ofstream out_file(file.c_str());

    if (!out_file.is_open()) {
        throw swd::exceptions::core_exception("Failed to write pid file");
    }

    out_file << getpid();
    out_file.close();
}

void swd::daemon::change_root(const std::string& directory) const {
    if (chroot(directory.c_str()) < 0) {
        throw swd::exceptions::core_exception("chroot() failed");
    }

    if (chdir("/") < 0) {
        throw swd::exceptions::core_exception("chdir() after chroot() failed");
    }
}

void swd::daemon::detach() const {
    /**
     * This forks the process, changes the current working directory to the
     * root directory and closes the standard input, standard output and
     * standard error (redirect to /dev/null).
     */
    if (::daemon(0, 0) < 0) {
        throw swd::exceptions::core_exception("daemon() failed");
    }
}
