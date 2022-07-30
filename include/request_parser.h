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

#ifndef REQUEST_PARSER_H
#define REQUEST_PARSER_H

#include <boost/logic/tribool.hpp>
#include <boost/tuple/tuple.hpp>

#include "request.h"

namespace swd {
    /**
     * @brief Parses the input of a client character by character.
     */
    class request_parser {
        public:
            /**
             * @brief Construct a request parser and set the state to the beginning.
             */
            request_parser();

            /**
             * @brief Parse some data.
             *
             * The tribool return value is true when a complete request has been
             * parsed, false if the data is invalid, indeterminate when more data
             * is required. The InputIterator return value indicates how much of
             * the input has been consumed.
             *
             * @param request The pointer to the request object
             * @param begin The beginning of the input iterator
             * @param end The end of the input iterator
             */
            template <typename InputIterator> boost::tuple<boost::tribool, InputIterator>
             parse(const swd::request_ptr& request, InputIterator begin, InputIterator end) {
                while (begin != end) {
                    boost::tribool result = consume(request, *begin++);

                    if (result || !result) {
                        return boost::make_tuple(result, begin);
                    }
                }
                boost::tribool result = boost::indeterminate;
                return boost::make_tuple(result, begin);
            }

        private:
            /**
             * @brief Consume the next character of the input.
             *
             * @param request The pointer to the request object
             * @param input The current character
             */
            boost::tribool consume(const swd::request_ptr& request,
             const char& input);

            /**
             * @brief The current state of the parser.
             */
            enum state {
                profile,
                signature,
                content
            } state_;
    };
}

#endif /* REQUEST_PARSER_H */
