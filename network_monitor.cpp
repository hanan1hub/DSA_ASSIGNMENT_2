#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/udp.h>  

#include <chrono>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <condition_variable>
#include <atomic>
#include <sstream>

using namespace std::chrono;
using std::cout;
using std::endl;
using std::string;

// Custom Stack 
template<typename T>
class Stack {
public:
    Stack(size_t init = 32) : cap(init), sz(0) {
        data = new T[cap];
    }
    ~Stack(){ 
        delete[] data; 
    }
    void push(const T& v) {
        if (sz == cap) {
            resize(cap * 2);
        }
        data[sz++] = v;
    }
    T pop() {
        if (sz == 0) {
            throw std::runtime_error("Stack underflow");
        }
        return data[--sz];
    }
    T& top() {
        if (sz == 0) {
            throw std::runtime_error("Stack empty");
        }
        return data[sz - 1];
    }
    bool empty() const { 
        return sz == 0; 
    }
    size_t size() const { 
        return sz; 
    }
private:
    void resize(size_t n) {
        T* nd = new T[n];
        for (size_t i = 0; i < sz; ++i) {
            nd[i] = data[i];
        }
        delete[] data;
        data = nd;
        cap = n;
    }
    T* data;
    size_t cap;
    size_t sz;
};

// Custom Queue 
template<typename T>
class Queue {
public:
    Queue(size_t init = 64) : cap(init), head(0), tail(0), cnt(0) {
        data = new T[cap];
    }
    ~Queue(){ 
        delete[] data; 
    }
    void push(const T& v) {
        if (cnt == cap) {
            resize(cap * 2);
        }
        data[tail] = v;
        tail = (tail + 1) % cap;
        ++cnt;
    }
    T pop() {
        if (cnt == 0) {
            throw std::runtime_error("Queue empty");
        }
        T v = data[head];
        head = (head + 1) % cap;
        --cnt;
        return v;
    }
    bool empty() const { 
        return cnt == 0; 
    }
    size_t size() const { 
        return cnt; 
    }
private:
    void resize(size_t n) {
        T* nd = new T[n];
        for (size_t i = 0; i < cnt; ++i) {
            nd[i] = data[(head + i) % cap];
        }
        delete[] data;
        data = nd;
        head = 0;
        tail = cnt;
        cap = n;
    }
    T* data;
    size_t cap;
    size_t head, tail, cnt;
};

// Packet definition 
struct Packet {
    uint64_t id;
    timeval tv;
    std::vector<uint8_t> buffer;
    std::string src_ip;
    std::string dst_ip;
    size_t size;
    int replay_attempts = 0;
    bool parsed = false;
};

// Globals 
std::atomic<uint64_t> g_packet_id{1};

// Queues with thread-safety
Queue<Packet> packetQueue;        // Captured packets to dissect
Queue<Packet> dissectedQueue;     // Dissected / ready-to-filter
Queue<Packet> replayQueue;        // Packets to replay
Queue<Packet> backupQueue;        // Failed replay backup list

std::mutex packetMutex;
std::condition_variable packetCv;

std::mutex dissectMutex;
std::condition_variable dissectCv;

std::mutex replayMutex;
std::condition_variable replayCv;

std::atomic<bool> running{true};

// Oversize handling
const size_t MAX_MTU = 1500;
const size_t OVERSIZE_THRESHOLD = 10; 

// Replay retry cap
const int MAX_RETRIES = 2;

// Filter IPs
std::string FILTER_SRC;
std::string FILTER_DST;

// For display
std::mutex summaryMutex;
std::vector<std::string> recentSummaries;

// Utility helpers 
std::string timeval_to_string(const timeval& tv) {
    char buf[64];
    time_t t = tv.tv_sec;
    struct tm tm;
    localtime_r(&t, &tm);
    int ms = tv.tv_usec / 1000;
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    char full[80];
    snprintf(full, sizeof(full), "%s.%03d", buf, ms);
    return std::string(full);
}

std::string mac_to_string(const uint8_t* mac) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

// Parsers (Ethernet, IPv4, IPv6, TCP, UDP) 
enum LayerType { L_ETHERNET, L_IPV4, L_IPV6, L_TCP, L_UDP, L_UNKNOWN };

struct Layer {
    LayerType type;
    size_t offset;
};

void dissect_packet_layers(Packet &p, std::vector<Layer>& layers) {
    Stack<Layer> st;
    st.push({L_ETHERNET, 0});

    while (!st.empty()) {
        Layer cur = st.pop();
        if (cur.type == L_ETHERNET) {
            if (p.size < cur.offset + sizeof(ether_header)) {
                continue;
            }
            const ether_header* eth = reinterpret_cast<const ether_header*>(p.buffer.data() + cur.offset);
            uint16_t ethertype = ntohs(eth->ether_type);
            if (ethertype == ETH_P_IP) {
                st.push({L_IPV4, cur.offset + sizeof(ether_header)});
                layers.push_back(cur);
            } 
            else if (ethertype == ETH_P_IPV6) {
                st.push({L_IPV6, cur.offset + sizeof(ether_header)});
                layers.push_back(cur);
            } 
            else {
                layers.push_back({L_UNKNOWN, cur.offset});
            }
        } 
        else if (cur.type == L_IPV4) {
            if (p.size < cur.offset + sizeof(ip)) {
                continue;
            }
            const ip* iph = reinterpret_cast<const ip*>(p.buffer.data() + cur.offset);
            int ihl = iph->ip_hl * 4;
            char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(iph->ip_src), src, sizeof(src));
            inet_ntop(AF_INET, &(iph->ip_dst), dst, sizeof(dst));
            p.src_ip = src;
            p.dst_ip = dst;
            layers.push_back(cur);
            // check protocol
            if (iph->ip_p == IPPROTO_TCP) {
                st.push({L_TCP, cur.offset + ihl});
            } 
            else if (iph->ip_p == IPPROTO_UDP) {
                st.push({L_UDP, cur.offset + ihl});
            }
        } 
        else if (cur.type == L_IPV6) {
            if (p.size < cur.offset + sizeof(ip6_hdr)) {
                continue;
            }
            const ip6_hdr* ip6h = reinterpret_cast<const ip6_hdr*>(p.buffer.data() + cur.offset);
            char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ip6h->ip6_src, src, sizeof(src));
            inet_ntop(AF_INET6, &ip6h->ip6_dst, dst, sizeof(dst));
            p.src_ip = src;
            p.dst_ip = dst;
            layers.push_back(cur);
            // Next header protocol
            if (ip6h->ip6_nxt == IPPROTO_TCP) {
                st.push({L_TCP, cur.offset + sizeof(ip6_hdr)});
            } 
            else if (ip6h->ip6_nxt == IPPROTO_UDP) {
                st.push({L_UDP, cur.offset + sizeof(ip6_hdr)});
            }
        } 
        else if (cur.type == L_TCP) {
            if (p.size < cur.offset + sizeof(tcphdr)) {
                continue;
            }
            const tcphdr* tcph = reinterpret_cast<const tcphdr*>(p.buffer.data() + cur.offset);
            layers.push_back(cur);
        } 
        else if (cur.type == L_UDP) {
            if (p.size < cur.offset + sizeof(udphdr)) {
                continue;
            }
            const udphdr* udph = reinterpret_cast<const udphdr*>(p.buffer.data() + cur.offset);
            layers.push_back(cur);
        } 
        else {
            layers.push_back(cur);
        }
    }
    p.parsed = true;
}

// Raw socket capture 
int create_raw_socket_bind(const char* ifname, int &sock, struct sockaddr_ll &sll) {
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        close(sock);
        return -1;
    }
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
        perror("bind");
        close(sock);
        return -1;
    }
    return 0;
}

void capture_thread_fn(const char* ifname) {
    int sock;
    struct sockaddr_ll sll;
    if (create_raw_socket_bind(ifname, sock, sll) != 0) {
        cout << "Capture socket creation failed. Exiting capture thread." << endl;
        running = false;
        return;
    }
    cout << "Capture thread: raw socket bound to interface " << ifname << endl;

    const size_t BUF_SZ = 65536;
    std::vector<uint8_t> buf(BUF_SZ);
    while (running) {
        ssize_t len = recv(sock, buf.data(), BUF_SZ, 0);
        if (len < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recv");
            break;
        }
        Packet p;
        p.id = g_packet_id.fetch_add(1);
        gettimeofday(&p.tv, nullptr);
        p.buffer.assign(buf.begin(), buf.begin() + len);
        p.size = static_cast<size_t>(len);
        {
            std::lock_guard<std::mutex> lk(packetMutex);
            packetQueue.push(p);
        }
        packetCv.notify_one();

        {
            std::lock_guard<std::mutex> lk(summaryMutex);
            std::ostringstream ss;
            ss << "CAP ID=" << p.id << " size=" << p.size << " time=" << timeval_to_string(p.tv);
            recentSummaries.push_back(ss.str());
            if (recentSummaries.size() > 20) {
                recentSummaries.erase(recentSummaries.begin());
            }
        }
    }
    close(sock);
}

// Dissector thread 
void dissector_thread_fn() {
    while (running) {
        Packet p;
        {
            std::unique_lock<std::mutex> lk(packetMutex);
            packetCv.wait_for(lk, std::chrono::milliseconds(500), []{ 
                return !packetQueue.empty() || !running; 
            });
            if (!running && packetQueue.empty()) {
                break;
            }
            if (packetQueue.empty()) {
                continue;
            }
            p = packetQueue.pop();
        }
        std::vector<Layer> layers;
        dissect_packet_layers(p, layers);
        {
            std::lock_guard<std::mutex> lk(dissectMutex);
            dissectedQueue.push(p);
        }
        dissectCv.notify_one();

        // summary
        {
            std::lock_guard<std::mutex> lk(summaryMutex);
            std::ostringstream ss;
            ss << "DSC ID=" << p.id << " src=" << (p.src_ip.empty() ? "-" : p.src_ip)
               << " dst=" << (p.dst_ip.empty() ? "-" : p.dst_ip)
               << " size=" << p.size;
            recentSummaries.push_back(ss.str());
            if (recentSummaries.size() > 30) {
                recentSummaries.erase(recentSummaries.begin());
            }
        }
    }
}

// Replay helpers 
bool raw_socket_send_on_iface(const char* ifname, const Packet& p) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("send socket");
        return false;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX send");
        close(sock);
        return false;
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_halen = ETH_ALEN;
    if (p.size >= (ssize_t)sizeof(ether_header)) {
        const ether_header* eth = reinterpret_cast<const ether_header*>(p.buffer.data());
        memcpy(sll.sll_addr, eth->ether_dhost, 6);
    } 
    else {
        memset(sll.sll_addr, 0xff, 6);
    }
    ssize_t sent = sendto(sock, p.buffer.data(), p.size, 0, (struct sockaddr*)&sll, sizeof(sll));
    close(sock);
    return sent == (ssize_t)p.size;
}

// Filter and replay thread 
void filter_replay_thread_fn(const char* iface) {
    size_t oversize_count = 0;
    while (running) {
        Packet p;
        {
            std::unique_lock<std::mutex> lk(dissectMutex);
            dissectCv.wait_for(lk, std::chrono::milliseconds(400), []{ 
                return !dissectedQueue.empty() || !running; 
            });
            if (!running ) {
                break;
            }
            if (dissectedQueue.empty()) {
                continue;
            }
            p = dissectedQueue.pop();
        }
        bool src_match = (FILTER_SRC.empty() || p.src_ip == FILTER_SRC);
        bool dst_match = (FILTER_DST.empty() || p.dst_ip == FILTER_DST);

        if (p.size > MAX_MTU) {
            oversize_count++;
        }
        bool skip_due_to_oversize = (p.size > MAX_MTU && oversize_count > OVERSIZE_THRESHOLD);

        if (src_match && dst_match && !skip_due_to_oversize) {
            // push to replay list
            {
                std::lock_guard<std::mutex> lk(replayMutex);
                replayQueue.push(p);
            }
            replayCv.notify_one();

            // display filtered
            {
                std::lock_guard<std::mutex> lk(summaryMutex);
                std::ostringstream ss;
                double delay_ms = (double)p.size / 1000.0;
                ss << "FLT ID=" << p.id << " src=" << p.src_ip << " dst=" << p.dst_ip
                   << " size=" << p.size << " est_delay(ms)=" << std::fixed << std::setprecision(3) << delay_ms;
                recentSummaries.push_back(ss.str());
                if (recentSummaries.size() > 40) {
                    recentSummaries.erase(recentSummaries.begin());
                }
            }
        } 
        else {
            // skip // will put here something if needed 
        }

        while (!replayQueue.empty()) {
            Packet rp;
            {
                std::lock_guard<std::mutex> lk(replayMutex);
                rp = replayQueue.pop();
            }
            double delay_ms = (double)rp.size / 1000.0;
            // simulate delay
            if (delay_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds((int)delay_ms));
            }

            bool sent = raw_socket_send_on_iface(iface, rp);
            if (!sent) {
                rp.replay_attempts++;
                if (rp.replay_attempts <= MAX_RETRIES) {
                    {
                        std::lock_guard<std::mutex> lk(replayMutex);
                        replayQueue.push(rp);
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(100)); 
                } 
                else {
                    // move to backup
                    {
                        std::lock_guard<std::mutex> lk(replayMutex);
                        backupQueue.push(rp);
                    }
                    {
                        std::lock_guard<std::mutex> lk(summaryMutex);
                        std::ostringstream ss;
                        ss << "BKUP ID=" << rp.id << " failed_retries=" << rp.replay_attempts << " size=" << rp.size;
                        recentSummaries.push_back(ss.str());
                        if (recentSummaries.size() > 60) {
                            recentSummaries.erase(recentSummaries.begin());
                        }
                    }
                }
            } 
            else {
                // success
                {
                    std::lock_guard<std::mutex> lk(summaryMutex);
                    std::ostringstream ss;
                    ss << "REPLAYED ID=" << rp.id << " attempts=" << rp.replay_attempts << " size=" << rp.size;
                    recentSummaries.push_back(ss.str());
                    if (recentSummaries.size() > 60) {
                        recentSummaries.erase(recentSummaries.begin());
                    }
                }
            }
        }
    }
}

// Display thread 
void display_thread_fn() {
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        std::lock_guard<std::mutex> lk(summaryMutex);
        cout << " Recent summaries " << endl;
        for (const auto &s : recentSummaries) {
            cout << s << endl;
        }
        cout<<endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        cout << "Usage: sudo " << argv[0] << " <interface> <filter-src-ip> <filter-dst-ip>\n";
        cout << "Use '-' to wildcard filter (i.e., match any)\n";
        return 1;
    }
    const char* iface = argv[1];
    string fs = argv[2];
    string fd = argv[3];
    if (fs != "-") {
        FILTER_SRC = fs;
    }
    if (fd != "-") {
        FILTER_DST = fd;
    }

    cout << "Starting Network Monitor on interface: " << iface << endl;
    if (!FILTER_SRC.empty()) {
        cout << "Filtering SRC IP: " << FILTER_SRC << endl;
    }
    if (!FILTER_DST.empty()) {
        cout << "Filtering DST IP: " << FILTER_DST << endl;
    }
    cout << "NOTE: Runing as root for raw sockets." << endl;

    // Start threads
    std::thread cap_thread(capture_thread_fn, iface);
    std::thread disc_thread(dissector_thread_fn);
    std::thread fr_thread(filter_replay_thread_fn, iface);
    std::thread disp_thread(display_thread_fn);

    // Run capture for at least 60 seconds as requested
    auto start = steady_clock::now();
    while (duration_cast<seconds>(steady_clock::now() - start).count() < 60) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    cout << "60 seconds demo complete. shutdown..." << endl;
    running = false;

    // wake all threads
    packetCv.notify_all();
    dissectCv.notify_all();
    replayCv.notify_all();

    cap_thread.join();
    disc_thread.join();
    fr_thread.join();
    disp_thread.join();

    // Show final backup list
    cout << "Final backup list (failed replays):" << endl;
    while (!backupQueue.empty()) {
        Packet bp = backupQueue.pop();
        cout << "Backup ID=" << bp.id << " src=" << bp.src_ip << " dst=" << bp.dst_ip
             << " size=" << bp.size << " attempts=" << bp.replay_attempts << endl;
    }

    cout << "Network Monitor terminated." << endl;
    return 0;
}