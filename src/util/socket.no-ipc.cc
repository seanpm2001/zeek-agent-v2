// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
//
// Limited Socket implementation supporting only communication within the same
// process. This is for platforms where we have not implemented IPC support
// yet.

#include "socket.h"

#include "core/logger.h"
#include "util/helpers.h"

#include <iostream>
#include <list>
#include <map>

using namespace zeek::agent;

socket::AddressHandle socket::Remote::pathToDestination(const filesystem::path& path) { return path.native(); }

// Global map of messages queued for each path/address.
using Message = std::pair<std::string, socket::AddressHandle>;
std::map<socket::AddressHandle, std::list<Message>> messages; // messages queued for each path

template<>
struct Pimpl<Socket>::Implementation {
    // Binds the socket to a local path, setting it up for communication.
    Result<Nothing> bind(const filesystem::path& path);

    // Reads one message from the socket. If no input is currently available,
    Result<Socket::ReadResult> read();

    // Sends one message to the currently active destination. This will fail
    Result<Nothing> write(const std::string& data, const socket::Remote& dst);

    Socket* _socket = nullptr;  // socket that this implementation belongs to
    filesystem::path _path;     // path the socket is bound to
    socket::AddressHandle _idx; // map into messages
};

Result<Nothing> Socket::Implementation::bind(const filesystem::path& path) {
    _path = path;
    _idx = _path.native();
    messages[_idx] = {};
    return Nothing();
}

Result<Socket::ReadResult> Socket::Implementation::read() {
    auto i = messages.find(_idx);
    if ( i == messages.end() )
        return result::Error("socket not bound", _path.native());

    if ( i->second.empty() )
        return {std::nullopt};

    auto msg = i->second.front();
    i->second.pop_front();

    return std::make_optional(std::make_pair(msg.first, socket::Remote(_socket, msg.second)));
}

Result<Nothing> Socket::Implementation::write(const std::string& data, const socket::Remote& dst) {
    auto i = messages.find(dst.destination());
    if ( i == messages.end() )
        return result::Error("socket not bound", dst.destination());

    i->second.emplace_back(data, _idx);
    return Nothing();
}

Socket::Socket() { pimpl()->_socket = this; }

Socket::~Socket() {}

bool Socket::isActive() const { return ! pimpl()->_path.empty(); };

Result<Nothing> Socket::bind(const filesystem::path& path) { return pimpl()->bind(path); }

Result<Socket::ReadResult> Socket::read() { return pimpl()->read(); }

Result<Nothing> Socket::write(const std::string& data, const socket::Remote& dst) { return pimpl()->write(data, dst); }

bool Socket::supportsIPC() { return false; }
