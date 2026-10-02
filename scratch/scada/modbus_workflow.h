#pragma once

// Optional behavioural Modbus model: FC03 and FC23 PDU shapes inside the
// project's existing 8-byte transaction/length envelope (NOT wire MBAP).
// RF receives only lengths/times/directions, never these decoded fields.
#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

namespace scada_modbus_workflow {
inline uint16_t Read16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
inline void Write16(uint8_t* p, uint16_t value) {
    p[0] = static_cast<uint8_t>(value >> 8);
    p[1] = static_cast<uint8_t>(value);
}
inline void Write32(uint8_t* p, uint32_t value) {
    for (int n = 0; n < 4; ++n)
        p[n] = static_cast<uint8_t>(value >> (24 - 8*n));
}
struct Request {
    uint8_t function = 3;
    uint16_t readStart = 0, readCount = 1;
    uint16_t writeStart = 0;
    std::vector<uint16_t> values;
};
inline std::vector<uint8_t> BuildRequest(uint32_t transaction,
                                       uint16_t reads, uint16_t writes,
                                       uint16_t value,
                                       uint16_t readStart = 0,
                                       uint16_t writeStart = 0) {
    readStart = std::min<uint16_t>(readStart, 124);
    writeStart = std::min<uint16_t>(writeStart, 124);
    reads = std::clamp<uint16_t>(reads, 1, 125-readStart);
    writes = std::min<uint16_t>(writes, std::min<uint16_t>(121,125-writeStart));
    std::vector<uint8_t> bytes(writes ? 18 + 2*writes : 13, 0);
    Write32(bytes.data(), transaction);
    Write32(bytes.data()+4, static_cast<uint32_t>(bytes.size()));
    bytes[8] = writes ? 23 : 3;
    Write16(bytes.data()+9, readStart);
    Write16(bytes.data()+11, reads);
    if (writes) {
        Write16(bytes.data()+13, writeStart);
        Write16(bytes.data()+15, writes);
        bytes[17] = static_cast<uint8_t>(2*writes);
        for (uint16_t n = 0; n < writes; ++n)
            Write16(bytes.data()+18+2*n, static_cast<uint16_t>(value+n));
    }
    return bytes;
}
inline bool ParseRequest(const uint8_t* bytes, uint32_t size, Request& request) {
    if (size < 13 || (bytes[8] != 3 && bytes[8] != 23)) return false;
    Request parsed;
    parsed.function = bytes[8];
    parsed.readStart = Read16(bytes+9);
    parsed.readCount = Read16(bytes+11);
    if (!parsed.readCount || parsed.readCount > 125
        || parsed.readStart + parsed.readCount > 125) return false;
    if (parsed.function == 3) {
        if (size != 13) return false;
    } else {
        if (size < 18) return false;
        parsed.writeStart = Read16(bytes+13);
        const uint16_t count = Read16(bytes+15);
        if (!count || count > 121 || parsed.writeStart + count > 125
            || bytes[17] != 2*count || size != 18+2u*count) return false;
        for (uint16_t n = 0; n < count; ++n)
            parsed.values.push_back(Read16(bytes+18+2*n));
    }
    request = parsed;
    return true;
}
inline std::vector<uint8_t> Execute(uint32_t transaction, const Request& request,
                                   std::array<uint16_t,125>& registers) {
    // FC23 writes first, then reads back, as required by the application spec.
    for (size_t n = 0; n < request.values.size(); ++n)
        registers.at(request.writeStart+n) = request.values[n];
    std::vector<uint8_t> bytes(10 + 2*request.readCount, 0);
    Write32(bytes.data(), transaction);
    Write32(bytes.data()+4, static_cast<uint32_t>(bytes.size()));
    bytes[8] = request.function;
    bytes[9] = static_cast<uint8_t>(2*request.readCount);
    for (uint16_t n = 0; n < request.readCount; ++n)
        Write16(bytes.data()+10+2*n, registers.at(request.readStart+n));
    return bytes;
}
} // namespace scada_modbus_workflow
