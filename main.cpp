#include <fmt/core.h>
#include <fmt/chrono.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/TcpReassembly.h>
#include <pcapplusplus/Packet.h>
#include <fstream>
#include <map>
#include <string>
#include <memory>
#include <vector>
#include <cstring>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

using namespace pcpp;

// Структура для хранения данных TCP сессии
struct TcpSessionData
{
    std::ofstream outputFile;
    std::string fileName;
    uint32_t flowKey;
    bool isActive;
    std::vector<uint8_t> buffer;  // Буфер для накопления данных
    timeval lastPacketTime;  // Время последнего пакета
    
    TcpSessionData() : flowKey(0), isActive(false) 
    {
        lastPacketTime.tv_sec = 0;
        lastPacketTime.tv_usec = 0;
    }
};

// Глобальная карта для хранения данных сессий
std::map<uint32_t, TcpSessionData> sessionDataMap;

// Структура для WebSocket фрейма
struct WebSocketFrame
{
    bool fin;
    uint8_t opcode;
    bool masked;
    uint64_t payloadLength;
    uint32_t maskingKey;
    std::vector<uint8_t> payload;
    timeval timestamp;  // Время фрейма из pcap
};

// Парсинг WebSocket фрейма
bool parseWebSocketFrame(const uint8_t* data, size_t dataLen, size_t& offset, WebSocketFrame& frame)
{
    if (offset >= dataLen)
        return false;
    
    // Минимальный размер фрейма - 2 байта
    if (dataLen - offset < 2)
        return false;
    
    // Byte 0: FIN (1 bit) + RSV1-3 (3 bits) + Opcode (4 bits)
    uint8_t byte0 = data[offset++];
    frame.fin = (byte0 & 0x80) != 0;
    frame.opcode = byte0 & 0x0F;
    
    // Byte 1: MASK (1 bit) + Payload len (7 bits)
    uint8_t byte1 = data[offset++];
    frame.masked = (byte1 & 0x80) != 0;
    uint8_t payloadLenField = byte1 & 0x7F;
    
    // Определяем длину payload
    if (payloadLenField < 126)
    {
        frame.payloadLength = payloadLenField;
    }
    else if (payloadLenField == 126)
    {
        // Следующие 2 байта - длина
        if (dataLen - offset < 2)
            return false;
        frame.payloadLength = (static_cast<uint64_t>(data[offset]) << 8) | data[offset + 1];
        offset += 2;
    }
    else // payloadLenField == 127
    {
        // Следующие 8 байт - длина
        if (dataLen - offset < 8)
            return false;
        frame.payloadLength = 0;
        for (int i = 0; i < 8; i++)
        {
            frame.payloadLength = (frame.payloadLength << 8) | data[offset++];
        }
    }
    
    // Читаем маскирующий ключ, если есть
    if (frame.masked)
    {
        if (dataLen - offset < 4)
            return false;
        frame.maskingKey = (static_cast<uint32_t>(data[offset]) << 24) |
                          (static_cast<uint32_t>(data[offset + 1]) << 16) |
                          (static_cast<uint32_t>(data[offset + 2]) << 8) |
                          static_cast<uint32_t>(data[offset + 3]);
        offset += 4;
    }
    
    // Читаем payload
    if (dataLen - offset < frame.payloadLength)
        return false;
    
    frame.payload.resize(frame.payloadLength);
    std::memcpy(frame.payload.data(), data + offset, frame.payloadLength);
    offset += frame.payloadLength;
    
    // Расшифровываем маскированные данные
    if (frame.masked)
    {
        for (size_t i = 0; i < frame.payloadLength; i++)
        {
            frame.payload[i] ^= ((frame.maskingKey >> (8 * (3 - (i % 4)))) & 0xFF);
        }
    }
    
    return true;
}

// Форматирование времени из timeval в читаемый формат
std::string formatTimestamp(const timeval& tv)
{
    try
    {
        // Преобразуем timeval в time_t
        std::time_t timeT = tv.tv_sec;
        
        // Форматируем время (используем безопасную версию для Windows)
        std::tm tmBuf;
#ifdef _WIN32
        if (gmtime_s(&tmBuf, &timeT) != 0)
        {
            return "Invalid time";
        }
        std::tm* tm = &tmBuf;
#else
        std::tm* tm = std::gmtime_r(&timeT, &tmBuf);
        if (tm == nullptr)
        {
            return "Invalid time";
        }
#endif
        
        std::ostringstream oss;
        oss << std::put_time(tm, "%Y-%m-%d %H:%M:%S");
        oss << "." << std::setfill('0') << std::setw(6) << tv.tv_usec;
        oss << " UTC";
        
        return oss.str();
    }
    catch (...)
    {
        return "Invalid time";
    }
}

// Обработка WebSocket данных для сессии
void processWebSocketData(uint32_t flowKey, const uint8_t* data, size_t dataLen, const timeval& packetTime)
{
    auto& sessionData = sessionDataMap[flowKey];
    
    // Обновляем время последнего пакета
    sessionData.lastPacketTime = packetTime;
    
    // Добавляем данные в буфер
    size_t oldSize = sessionData.buffer.size();
    sessionData.buffer.resize(oldSize + dataLen);
    std::memcpy(sessionData.buffer.data() + oldSize, data, dataLen);
    
    // Парсим фреймы из буфера
    size_t processedBytes = 0;
    size_t bufferSizeBefore = sessionData.buffer.size();
    
    while (processedBytes < sessionData.buffer.size())
    {
        WebSocketFrame frame;
        size_t offset = processedBytes;
        size_t bytesAvailable = sessionData.buffer.size() - offset;
        
        if (!parseWebSocketFrame(sessionData.buffer.data(), sessionData.buffer.size(), offset, frame))
        {
            // Недостаточно данных для полного фрейма, оставляем в буфере
            // Логируем, если фрейм очень большой (возможна проблема)
            if (bytesAvailable >= 2)
            {
                uint8_t byte0 = sessionData.buffer[offset];
                uint8_t byte1 = sessionData.buffer[offset + 1];
                uint8_t opcode = byte0 & 0x0F;
                bool masked = (byte1 & 0x80) != 0;
                uint8_t payloadLenField = byte1 & 0x7F;
                
                // Если мы видим начало фрейма, но не можем его распарсить,
                // возможно, фрейм очень большой и приходит частями
                if (payloadLenField == 127 && bytesAvailable < 15) // 2 (заголовок) + 8 (длина) + 4 (маска) + 1 (минимальный payload)
                {
                    // Это нормально - большой фрейм приходит частями, ждем
                }
            }
            break;
        }
        
        // Сохраняем начальную позицию фрейма для возможного отката
        size_t frameStartOffset = processedBytes;
        processedBytes = offset;
        
        // Устанавливаем время фрейма (время пакета, из которого он был извлечен)
        frame.timestamp = packetTime;
        
        // Проверяем валидность опкода WebSocket
        // Валидные опкоды: 0 (Continuation), 1 (Text), 2 (Binary), 8 (Close), 9 (Ping), 10 (Pong)
        // 3-7 и 11-15 зарезервированы и не должны встречаться в нормальных фреймах
        // Если мы видим зарезервированные опкоды, возможно, парсер сбился и интерпретирует
        // часть payload предыдущего фрейма как начало нового фрейма
        bool validOpcode = (frame.opcode == 0 || frame.opcode == 1 || frame.opcode == 2 || 
                           frame.opcode == 8 || frame.opcode == 9 || frame.opcode == 10);
        if (!validOpcode)
        {
            // Зарезервированный опкод - возможна ошибка парсинга
            // Это означает, что мы пытаемся парсить данные из середины предыдущего фрейма
            // Откатываем offset назад к началу этого "фрейма" и прекращаем парсинг
            std::string errorInfo = fmt::format("\n[ERROR: Reserved WebSocket opcode {} detected at offset {} (frame start: {}) - parser desynchronized, stopping frame parsing]\n", 
                frame.opcode, frameStartOffset, frameStartOffset);
            sessionData.outputFile.write(errorInfo.c_str(), errorInfo.length());
            sessionData.outputFile.flush();
            
            // Откатываем обработанные байты к началу этого фрейма - не удаляем эти данные из буфера
            // Они могут быть частью незаконченного большого фрейма или поврежденных данных
            processedBytes = frameStartOffset;
            break;
        }
        
        // Проверка на разумность размера фрейма для предотвращения парсинга мусора
        // Если фрейм слишком большой (например, > 10MB), это может быть ошибка парсинга
        const size_t MAX_REASONABLE_FRAME_SIZE = 10 * 1024 * 1024; // 10 MB
        if (frame.payloadLength > MAX_REASONABLE_FRAME_SIZE)
        {
            std::string errorInfo = fmt::format("\n[ERROR: Frame size {} exceeds maximum reasonable size {} - possible parsing error]\n", 
                frame.payloadLength, MAX_REASONABLE_FRAME_SIZE);
            sessionData.outputFile.write(errorInfo.c_str(), errorInfo.length());
            sessionData.outputFile.flush();
            processedBytes = frameStartOffset;
            break;
        }
        
        // Записываем расшифрованные данные в файл
        if (frame.payloadLength > 0 && sessionData.outputFile.is_open())
        {
            // Записываем информацию о фрейме с временем
            std::string frameInfo = fmt::format("\n--- WebSocket Frame ---\n");
            frameInfo += fmt::format("Time: {}\n", formatTimestamp(frame.timestamp));
            frameInfo += fmt::format("FIN: {}, Opcode: {}, Masked: {}, Length: {}\n", 
                frame.fin, frame.opcode, frame.masked, frame.payloadLength);
            sessionData.outputFile.write(frameInfo.c_str(), frameInfo.length());
            
            // Записываем payload
            sessionData.outputFile.write(reinterpret_cast<const char*>(frame.payload.data()), frame.payloadLength);
            sessionData.outputFile.write("\n", 1);
            sessionData.outputFile.flush();
        }
    }
    
    // Удаляем обработанные данные из буфера
    if (processedBytes > 0)
    {
        std::vector<uint8_t> remaining(sessionData.buffer.begin() + processedBytes, sessionData.buffer.end());
        sessionData.buffer = std::move(remaining);
    }
}

// Callback для обработки новых TCP данных
void onTcpMessageReady(int8_t side, const TcpStreamData& tcpData, void* userCookie)
{
    const ConnectionData& connData = tcpData.getConnectionData();
    uint32_t flowKey = connData.flowKey;
    
    // Получаем или создаем запись для этой сессии
    auto& sessionData = sessionDataMap[flowKey];
    
    if (!sessionData.isActive)
    {
        // Создаем файл для этой сессии
        sessionData.fileName = fmt::format("websocket_session_{}_{}_{}_{}_{}.txt",
            connData.srcIP.toString(), connData.srcPort,
            connData.dstIP.toString(), connData.dstPort,
            flowKey);
        sessionData.outputFile.open(sessionData.fileName, std::ios::binary | std::ios::app);
        sessionData.flowKey = flowKey;
        sessionData.isActive = true;
        
        fmt::print("Создана новая WebSocket сессия: {} -> {}:{}\n",
            connData.srcIP.toString(), connData.dstIP.toString(), connData.dstPort);
    }
    
    // Получаем данные
    const uint8_t* data = tcpData.getData();
    size_t dataLen = tcpData.getDataLength();
    
    if (dataLen > 0)
    {
        // Получаем время пакета из pcap
        timeval packetTime = tcpData.getTimeStamp();
        
        // Обрабатываем как WebSocket данные
        processWebSocketData(flowKey, data, dataLen, packetTime);
        
        // Если есть пропущенные байты, добавляем маркер
        if (tcpData.isBytesMissing())
        {
            std::string missingMarker = fmt::format("\n[{} bytes missing]\n", tcpData.getMissingByteCount());
            sessionData.outputFile.write(missingMarker.c_str(), missingMarker.length());
        }
    }
}

// Callback для начала TCP соединения
void onTcpConnectionStart(const ConnectionData& connectionData, void* userCookie)
{
    fmt::print("Начало TCP соединения: {}:{} -> {}:{}\n",
        connectionData.srcIP.toString(), connectionData.srcPort,
        connectionData.dstIP.toString(), connectionData.dstPort);
}

// Callback для окончания TCP соединения
void onTcpConnectionEnd(const ConnectionData& connectionData, TcpReassembly::ConnectionEndReason reason, void* userCookie)
{
    uint32_t flowKey = connectionData.flowKey;
    auto it = sessionDataMap.find(flowKey);
    
    if (it != sessionDataMap.end())
    {
        // Обрабатываем оставшиеся данные в буфере
        if (!it->second.buffer.empty() && (it->second.lastPacketTime.tv_sec != 0 || it->second.lastPacketTime.tv_usec != 0))
        {
            // Используем время последнего пакета для оставшихся данных
            processWebSocketData(flowKey, it->second.buffer.data(), it->second.buffer.size(), 
                               it->second.lastPacketTime);
        }
        
        if (it->second.outputFile.is_open())
        {
            it->second.outputFile.close();
        }
        
        fmt::print("Конец TCP соединения: {}:{} -> {}:{}, файл: {}\n",
            connectionData.srcIP.toString(), connectionData.srcPort,
            connectionData.dstIP.toString(), connectionData.dstPort,
            it->second.fileName);
        
        it->second.isActive = false;
    }
}

int main()
{
    const std::string pcapFileName = "capture/capture2.htm";
    
    fmt::print("Чтение pcap файла: {}\n", pcapFileName);
    
    // Пробуем открыть как pcap файл
    IFileReaderDevice* reader = nullptr;
    std::unique_ptr<PcapFileReaderDevice> pcapReader;
    std::unique_ptr<PcapNgFileReaderDevice> pcapngReader;
    
    // Сначала пробуем как обычный pcap
    pcapReader = std::make_unique<PcapFileReaderDevice>(pcapFileName);
    if (pcapReader->open())
    {
        reader = pcapReader.get();
        fmt::print("Файл открыт как pcap\n");
    }
    else
    {
        pcapReader->close();
        pcapReader.reset();
        // Пробуем как pcapng
        pcapngReader = std::make_unique<PcapNgFileReaderDevice>(pcapFileName);
        if (pcapngReader->open())
        {
            reader = pcapngReader.get();
            fmt::print("Файл открыт как pcapng\n");
        }
        else
        {
            fmt::print(stderr, "Ошибка: не удалось открыть файл {} ни как pcap, ни как pcapng\n", pcapFileName);
            return 1;
        }
    }
    
    fmt::print("Файл успешно открыт\n");
    
    // Создаем TcpReassembly с нашими callbacks
    TcpReassembly tcpReassembly(onTcpMessageReady, nullptr, onTcpConnectionStart, onTcpConnectionEnd);
    
    RawPacket rawPacket;
    int packetCount = 0;
    
    // Читаем пакеты из файла
    while (reader->getNextPacket(rawPacket))
    {
        packetCount++;
        
        // Парсим пакет
        Packet parsedPacket(&rawPacket);
        
        // Обрабатываем пакет через TCP reassembly
        TcpReassembly::ReassemblyStatus status = tcpReassembly.reassemblePacket(parsedPacket);
        
        // Выводим информацию о статусе (опционально, для отладки)
        if (packetCount % 100 == 0)
        {
            fmt::print("Обработано пакетов: {}\n", packetCount);
        }
    }
    
    fmt::print("Всего обработано пакетов: {}\n", packetCount);
    
    // Закрываем все открытые соединения
    tcpReassembly.closeAllConnections();
    
    // Закрываем все файлы
    for (auto& pair : sessionDataMap)
    {
        if (pair.second.outputFile.is_open())
        {
            pair.second.outputFile.close();
        }
    }
    
    // Закрываем reader
    reader->close();
    pcapReader.reset();
    pcapngReader.reset();
    
    fmt::print("Обработка завершена. Создано WebSocket сессий: {}\n", sessionDataMap.size());
    
    return 0;
}
