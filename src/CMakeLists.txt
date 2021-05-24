include_directories(${SHADOWD_SOURCE_DIR}/dist)
include_directories(${SHADOWD_SOURCE_DIR}/include)
link_directories(${SHADOWD_BINARY_DIR}/src)

add_executable(shadowd
    blacklist_filter.cpp
    cache.cpp
    config.cpp
    daemon.cpp
    log.cpp
    profile.cpp
    reply_handler.cpp
    request_handler.cpp
    server.cpp
    storage.cpp
    whitelist_filter.cpp
    blacklist.cpp
    blacklist_rule.cpp
    connection.cpp
    database.cpp
    parameter.cpp
    reply.cpp
    request.cpp
    request_parser.cpp
    shadowd.cpp
    whitelist.cpp
    whitelist_rule.cpp
    integrity.cpp
    integrity_rule.cpp
    hash.cpp
    core_exception.cpp
    config_exception.cpp
    connection_exception.cpp
    database_exception.cpp
    ${SHADOWD_SOURCE_DIR}/dist/jsoncpp.cpp
)

target_link_libraries(shadowd
    pthread
    dbi
    cryptopp
    ${OPENSSL_LIBRARIES}
    ${Boost_LIBRARIES}
)

install(TARGETS shadowd
    RUNTIME DESTINATION bin
)
