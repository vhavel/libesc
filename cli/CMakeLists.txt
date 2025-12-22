# CLI sources
set(CLI_SOURCES
    main.cpp
)

add_executable(esc ${CLI_SOURCES})
target_link_libraries(esc PRIVATE libesc Zydis)

# Install CLI
install(TARGETS esc
    RUNTIME DESTINATION bin
)
