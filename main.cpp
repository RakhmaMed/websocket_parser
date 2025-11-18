#define NOMINMAX
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

// Максимальный разумный размер буфера сессии (50 MB) для предотвращения DoS/OOM
const size_t MAX_SESSION_BUFFER_SIZE = 50 * 1024 * 1024;

// Структура для хранения данных TCP сессии
struct TcpSessionData
{
    std::ofstream outputFile;
    std::string fileName;
    uint32_t flowKey;
    bool isActive;
    std::vector<uint8_t> buffer[2];  // Буферы для двух направлений (0 и 1)
    timeval lastPacketTime;  // Время последнего пакета
    
    TcpSessionData() : flowKey(0), isActive(false) 
    {
        lastPacketTime.tv_sec = 0;
        lastPacketTime.tv_usec = 0;
    }
};

// Структура контекста приложения для передачи в callback'и
struct AppContext
{
    std::string outputFileName;
    std::map<uint32_t, TcpSessionData> sessionDataMap;
};

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

// Вспомогательная функция для Hex дампа
std::string hexDump(const uint8_t* data, size_t size, size_t limit = 32)
{
    std::ostringstream oss;
    for (size_t i = 0; i < (std::min)(size, limit); ++i)
    {
        oss << fmt::format("{:02X} ", data[i]);
    }
    if (size > limit) oss << "...";
    return oss.str();
}

// Парсинг WebSocket фрейма
bool parseWebSocketFrame(const uint8_t* data, size_t dataLen, size_t& offset, WebSocketFrame& frame, std::string& errorLog)
{
    if (offset >= dataLen)
        return false;
    
    // Сохраняем начальный offset для отладки
    size_t startOffset = offset;
    
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
void processWebSocketData(TcpSessionData& sessionData, int8_t side, const uint8_t* data, size_t dataLen, const timeval& packetTime)
{
    // Обновляем время последнего пакета
    sessionData.lastPacketTime = packetTime;
    
    auto& buffer = sessionData.buffer[side];

    // Проверка на переполнение буфера
    if (buffer.size() + dataLen > MAX_SESSION_BUFFER_SIZE)
    {
        std::string errorInfo = fmt::format("\n[ERROR: Session buffer (side {}) exceeded limit ({} bytes). Dropping connection data to prevent memory overflow]\n", side, MAX_SESSION_BUFFER_SIZE);
        if (sessionData.outputFile.is_open())
        {
            sessionData.outputFile.write(errorInfo.c_str(), errorInfo.length());
            sessionData.outputFile.flush();
        }
        // Очищаем буфер, чтобы не копить старые данные
        buffer.clear();
        return;
    }

    // Добавляем данные в буфер
    if (dataLen > 0)
    {
        size_t oldSize = buffer.size();
        buffer.resize(oldSize + dataLen);
        std::memcpy(buffer.data() + oldSize, data, dataLen);
    }
    
    // Парсим фреймы из буфера
    size_t processedBytes = 0;
    size_t bufferSizeBefore = buffer.size();
    
    while (processedBytes < buffer.size())
    {
        WebSocketFrame frame;
        size_t offset = processedBytes;
        size_t bytesAvailable = buffer.size() - offset;
        std::string errorLog; // Для сбора информации об ошибке
        
        if (!parseWebSocketFrame(buffer.data(), buffer.size(), offset, frame, errorLog))
        {
            // Недостаточно данных для полного фрейма, оставляем в буфере
            // Логируем, если фрейм очень большой (возможна проблема)
            if (bytesAvailable >= 2)
            {
                uint8_t byte0 = buffer[offset];
                uint8_t byte1 = buffer[offset + 1];
                uint8_t payloadLenField = byte1 & 0x7F;
                
                // Если мы видим начало фрейма, но не можем его распарсить,
                // возможно, фрейм очень большой и приходит частями
                if (payloadLenField == 127 && bytesAvailable < 15) 
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
        bool validOpcode = (frame.opcode == 0 || frame.opcode == 1 || frame.opcode == 2 || 
                           frame.opcode == 8 || frame.opcode == 9 || frame.opcode == 10);
        if (!validOpcode)
        {
            // Генерируем Hex дамп вокруг места ошибки
            size_t dumpStart = (frameStartOffset > 32) ? frameStartOffset - 32 : 0;
            std::string contextDump = hexDump(buffer.data() + dumpStart, 64);
            
            std::string errorInfo = fmt::format("\n[ERROR: Reserved WebSocket opcode {} detected at offset {} (frame start: {}) in side {}]\n", 
                frame.opcode, frameStartOffset, frameStartOffset, side);
            errorInfo += fmt::format("Context Hex Dump (around offset {}): {}\n", frameStartOffset, contextDump);
            errorInfo += fmt::format("Buffer Size: {}, Payload Length: {}, Masked: {}\n", 
                buffer.size(), frame.payloadLength, frame.masked);
                
            if (sessionData.outputFile.is_open())
            {
                sessionData.outputFile.write(errorInfo.c_str(), errorInfo.length());
                sessionData.outputFile.flush();
            }
            
            // Попытка найти следующий валидный фрейм (brute-force sync)
            // Ищем байт, похожий на начало фрейма (например, 0x81 - Text, FIN)
            // Это примитивный эвристический поиск
            size_t searchOffset = frameStartOffset + 1;
            bool found = false;
            while (searchOffset < buffer.size() - 2) {
                uint8_t b0 = buffer[searchOffset];
                uint8_t opcode = b0 & 0x0F;
                if ((b0 & 0x80) && (opcode == 1 || opcode == 2 || opcode == 8)) {
                    // Нашли кандидата
                    found = true;
                    processedBytes = searchOffset;
                    std::string recoverMsg = fmt::format("[RECOVERY] Found potential frame start at offset {}. Skipping {} bytes.\n", searchOffset, searchOffset - frameStartOffset);
                    if (sessionData.outputFile.is_open()) sessionData.outputFile.write(recoverMsg.c_str(), recoverMsg.length());
                    break;
                }
                searchOffset++;
            }
            
            if (!found) {
                // Если не нашли, сбрасываем буфер, чтобы не зацикливаться
                processedBytes = buffer.size(); 
            }
            // Мы либо нашли новый старт (continue loop), либо сбросили буфер (break next iteration)
            continue; 
        }
        
        // Проверка на разумность размера фрейма для предотвращения парсинга мусора
        const size_t MAX_REASONABLE_FRAME_SIZE = 10 * 1024 * 1024; // 10 MB
        if (frame.payloadLength > MAX_REASONABLE_FRAME_SIZE)
        {
            std::string errorInfo = fmt::format("\n[ERROR: Frame size {} exceeds maximum reasonable size {} - possible parsing error]\n", 
                frame.payloadLength, MAX_REASONABLE_FRAME_SIZE);
            if (sessionData.outputFile.is_open())
            {
                sessionData.outputFile.write(errorInfo.c_str(), errorInfo.length());
                sessionData.outputFile.flush();
            }
            processedBytes = frameStartOffset;
            break;
        }
        
        // Записываем расшифрованные данные в файл
        if (frame.payloadLength > 0 && sessionData.outputFile.is_open())
        {
            // Записываем информацию о фрейме с временем
            std::string frameInfo = fmt::format("\n--- WebSocket Frame (Side {}) ---\n", side);
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
        buffer.erase(buffer.begin(), buffer.begin() + processedBytes);
    }
}

// Callback для обработки новых TCP данных
void onTcpMessageReady(int8_t side, const TcpStreamData& tcpData, void* userCookie)
{
    AppContext* ctx = static_cast<AppContext*>(userCookie);
    const ConnectionData& connData = tcpData.getConnectionData();
    uint32_t flowKey = connData.flowKey;
    
    // Получаем или создаем запись для этой сессии
    auto& sessionData = ctx->sessionDataMap[flowKey];
    
    if (!sessionData.isActive)
    {
        // Создаем файл для этой сессии
        sessionData.fileName = fmt::format("{}_{}_{}_{}_{}_{}.txt",
            ctx->outputFileName,
            connData.srcIP.toString(), connData.srcPort,
            connData.dstIP.toString(), connData.dstPort,
            flowKey);
            
        sessionData.outputFile.open(sessionData.fileName, std::ios::binary | std::ios::app);
        
        if (!sessionData.outputFile.is_open())
        {
            fmt::print(stderr, "Ошибка открытия файла для записи: {}\n", sessionData.fileName);
            // Не помечаем сессию как активную, если файл не открылся
            return;
        }
        
        sessionData.flowKey = flowKey;
        sessionData.isActive = true;
        
        fmt::print("Создана новая WebSocket сессия: {} -> {}:{}\n",
            connData.srcIP.toString(), connData.dstIP.toString(), connData.dstPort);
    }
    
    // Получаем данные
    const uint8_t* data = tcpData.getData();
    size_t dataLen = tcpData.getDataLength();
    
    // Сначала проверяем на наличие потерянных пакетов (разрывов потока)
    // TcpReassembly может вызвать этот callback с dataLen=0, чтобы сообщить о разрыве
    if (tcpData.isBytesMissing())
    {
        size_t missingCount = tcpData.getMissingByteCount();
        
        // Логируем факт потери
        if (sessionData.outputFile.is_open())
        {
             std::string missingMarker = fmt::format("\n[WARNING: Stream discontinuity detected in side {}. Inserting {} padding bytes to maintain sync]\n", side, missingCount);
             sessionData.outputFile.write(missingMarker.c_str(), missingMarker.length());
        }
        
        // Добавляем нули в буфер
        auto& buffer = sessionData.buffer[side];
        size_t oldSize = buffer.size();
        buffer.resize(oldSize + missingCount, 0);
    }

    // Затем обрабатываем данные, если они есть
    if (dataLen > 0)
    {
        // Получаем время пакета из pcap
        timeval packetTime = tcpData.getTimeStamp();
        
        // Обрабатываем как WebSocket данные
        processWebSocketData(sessionData, side, data, dataLen, packetTime);
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
    AppContext* ctx = static_cast<AppContext*>(userCookie);
    uint32_t flowKey = connectionData.flowKey;
    auto it = ctx->sessionDataMap.find(flowKey);
    
    if (it != ctx->sessionDataMap.end())
    {
        // Обрабатываем оставшиеся данные в буферах для обоих направлений
        for (int side = 0; side < 2; side++)
        {
            if (!it->second.buffer[side].empty() && (it->second.lastPacketTime.tv_sec != 0 || it->second.lastPacketTime.tv_usec != 0))
            {
                // Используем время последнего пакета для оставшихся данных
                processWebSocketData(it->second, side, nullptr, 0, it->second.lastPacketTime); 
            }
            
            // Проверяем, остались ли нераспаршенные данные
            if (!it->second.buffer[side].empty() && it->second.outputFile.is_open())
            {
                 std::string incompleteMsg = fmt::format("\n[WARNING: Connection ended with {} bytes of incomplete frame data in buffer (side {})]\n", it->second.buffer[side].size(), side);
                 it->second.outputFile.write(incompleteMsg.c_str(), incompleteMsg.length());
            }
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
        // Опционально: удаляем сессию из карты для освобождения памяти
        // ctx->sessionDataMap.erase(it);
    }
}

int main(int argc, char* argv[])
{
    // Проверяем аргументы командной строки
    if (argc < 3)
    {
        fmt::print(stderr, "Использование: {} <путь_к_pcap_файлу> <имя_выходного_файла>\n", argv[0]);
        fmt::print(stderr, "Пример: {} capture/capture2.pcap output.txt\n", argv[0]);
        return 1;
    }
    
    const std::string pcapFileName = argv[1];
    
    // Инициализируем контекст приложения
    AppContext ctx;
    ctx.outputFileName = argv[2];
    
    fmt::print("Чтение pcap файла: {}\n", pcapFileName);
    fmt::print("Выходной файл: {}\n", ctx.outputFileName);
    
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
    
    // Создаем TcpReassembly с нашими callbacks и передаем контекст
    TcpReassembly tcpReassembly(onTcpMessageReady, &ctx, onTcpConnectionStart, onTcpConnectionEnd);
    
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
        if (packetCount % 10000 == 0)
        {
            fmt::print("Обработано пакетов: {}\n", packetCount);
        }
    }
    
    fmt::print("Всего обработано пакетов: {}\n", packetCount);
    
    // Закрываем все открытые соединения
    tcpReassembly.closeAllConnections();
    
    // Закрываем все файлы (на всякий случай, хотя closeAllConnections вызовет onTcpConnectionEnd)
    for (auto& pair : ctx.sessionDataMap)
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
    
    fmt::print("Обработка завершена. Создано WebSocket сессий: {}\n", ctx.sessionDataMap.size());
    
    return 0;
}
