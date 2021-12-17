//g++ -std=c++11 xxx.cpp
#include <array>
#include <atomic>
#include <arpa/inet.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>                            //防止ctrl-C造成的退出带来的问题
#include <termios.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#define _YY_DEBUG_PRINT_
    
#pragma pack(1)
#define SDU_LEN_MAX          2048
#define $XY                  5855268
#define SduTarget2_Port      12345
#define SduApp1_self_IP      "127.0.0.1"      //本机IP地址，即接收端地址
#define SduApp1_self_Port    12345            //本机端口号，即接收端端口号
typedef struct {                              //含Flag位的sdu发送帧格式
    uint32_t Flag;                            //识别标识位
    uint8_t T;                                //占一位，为3时是ack为1时是sdu
    uint8_t priority;                         //sdu的优先级
    uint8_t seg_sn;                           //分段后的相对位置
    uint16_t sdu_length;                      //长度指示
    uint32_t sdu_sn;                          //序列号
    uint32_t service_type;                    //业务类型
    uint32_t sender_id;                       //发送者id
    uint8_t data[SDU_LEN_MAX];                //实际发送/接收数据
}SduFlagPack;

#define FATAL do { fprintf(stderr, "Error at line %d, file %s (%d) [%s]\n", \
  __LINE__, __FILE__, errno, strerror(errno)); exit(1); } while(0)

#define MAP_SIZE 4096UL
#define MAP_MASK (MAP_SIZE - 1)

using namespace std;
using namespace std::chrono;
using std::chrono::system_clock;

std::vector<std::string> mac_table{
    "20:c3:8f:ee:43:74", "20:c3:8f:ee:d6:b8", "20:c3:8f:ee:3f:7d"
};
std::vector<bool> mac_connect{false,false,false};
std::vector<std::string> ip_table{"", "", ""};
std::vector<uint8_t> mesh_info {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};    //传给FPGA和主机用

//打印至串口
ofstream ofs;

// >>>> GPMC configuration >>>>
int fd;
void *map_base1, *map_base2;
volatile uint16_t* gpmc_read_base_addr;
volatile uint16_t* gpmc_write_base_addr;
void yy_gpmc_init() {
    if((fd = open("/dev/mem", O_RDWR | O_SYNC)) == -1) FATAL;
    printf("/dev/mem opened.\n");
    fflush(stdout);
    off_t target1 = strtoul("0x03000000", 0, 0);
    off_t target2 = strtoul("0x04000000", 0, 0);
    map_base1 = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target1 & ~MAP_MASK);
    map_base2 = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target2 & ~MAP_MASK);
    if(map_base1 == (void *) -1) FATAL;
    if(map_base2 == (void *) -1) FATAL;
    gpmc_read_base_addr  = reinterpret_cast<uint16_t *>(map_base1);
    gpmc_write_base_addr = reinterpret_cast<uint16_t *>(map_base2);
}

void yy_gpmc_free() {
    if(munmap(map_base1, MAP_SIZE) == -1) FATAL;
    if(munmap(map_base2, MAP_SIZE) == -1) FATAL;
    close(fd);
}
// <<<< GPMC configuration <<<<

// >>>> socket configuration >>>>
int send_socket_1, recv_socket_1;
sockaddr_in send_addr_1, recv_addr_1, send_addr_2;
SduFlagPack SduFlagPack_0, SduFlagPack_1;
socklen_t send_addr_2_size;
uint16_t* send_buffer = reinterpret_cast<uint16_t*>(SduFlagPack_0.data);
uint16_t* receive_buffer = reinterpret_cast<uint16_t*>(SduFlagPack_1.data);
void yy_socket_init() {
    send_socket_1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 
    memset(&send_addr_1, 0, sizeof(send_addr_1));  //每个字节都用0填充
    send_addr_1.sin_family = AF_INET;  //使用IPv4地址
    send_addr_1.sin_addr.s_addr = inet_addr("127.0.0.1");  //具体的IP地址
    send_addr_1.sin_port = htons(SduTarget2_Port);  //端口
    SduFlagPack_0.Flag=$XY;
    SduFlagPack_0.T=1;
    SduFlagPack_0.sdu_sn=0;
    SduFlagPack_0.seg_sn=0;
    SduFlagPack_0.sender_id=111;
    SduFlagPack_0.service_type=2;
    recv_socket_1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);//创建服务器端socket ，使用面向消息的UDP
    if(recv_socket_1==-1) {
        #ifdef _YY_DEBUG_PRINT_
            ofs << "receiver socket set up failed" << endl;
        #endif
        return;
    }
    #ifdef _YY_DEBUG_PRINT_
        ofs << "receiver socket set up: success" << endl;
    #endif
                                //接收端ip地址 端口地址
    memset(&recv_addr_1, 0, sizeof(recv_addr_1));                  //每个字节都用0填充
    recv_addr_1.sin_family = AF_INET;                              //使用IPv4地址
    recv_addr_1.sin_addr.s_addr = inet_addr(SduApp1_self_IP);      //具体的IP地址
    recv_addr_1.sin_port = htons(SduApp1_self_Port);              //端口
    #ifdef _YY_DEBUG_PRINT_
        printf("本机IP:%s\n本机端口号:%d\n",SduApp1_self_IP,SduApp1_self_Port);
    #endif
    
    //设置监听套接字，使得重启之后不会影响绑定
    int on =1;
    if(setsockopt(recv_socket_1,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on))<0) {
        #ifdef _YY_DEBUG_PRINT_
            ofs << "Failed to set address reuse" << endl;
        #endif
        return;
    }
    #ifdef _YY_DEBUG_PRINT_
            ofs << "Setting address reuse succeeded" << endl;
    #endif

    //设置非阻塞
    struct timeval read_timeout;
    read_timeout.tv_sec = 0;
    read_timeout.tv_usec = 1000;    //1000us time-out;
    if(setsockopt(recv_socket_1,SOL_SOCKET,SO_RCVTIMEO ,&read_timeout,sizeof(read_timeout))<0) {
        #ifdef _YY_DEBUG_PRINT_
            ofs << "Failed to set to non-blocking mode" << endl;
        #endif
        return;
    }
    #ifdef _YY_DEBUG_PRINT_
        ofs << "receiver set to non-blocking mode succeeded" << endl;
    #endif
    
    //将端口地址，ip地址与socket进行绑定
    int r = bind(recv_socket_1, (struct sockaddr*)&recv_addr_1, sizeof(recv_addr_1));
     if(r==-1) {
        #ifdef _YY_DEBUG_PRINT_
            ofs << "binding port: failed" << endl;
        #endif
        return;
    }
    #ifdef _YY_DEBUG_PRINT_
        ofs << "binding port: success" << endl;
    #endif

    sockaddr_in send_addr_2;//用于返回发送方的地址
    send_addr_2_size = sizeof(send_addr_2);
}
// <<<< socket configuration <<<<


//执行shell命令, 结果以字符串返回
std::string execute(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

inline std::string execute(std::string cmd_str) {
    return execute(cmd_str.c_str());
}

//调整系统时间
chrono::system_clock::time_point t;
uint32_t last_time_stamp = 0;
void clocking(uint32_t time_stamp) {
    //time_t tt = static_cast<time_t>(time_stamp);std::stringstream ss;ss << put_time(std::localtime(&tt), "%F %T"); execute("date -s \"" + ss.str() + "\"");
    last_time_stamp = time_stamp;
    t = system_clock::now();
}

uint32_t get_system_time() {
    auto end = system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - t).count();
    uint32_t difff = (uint32_t)duration;
    long temp = (last_time_stamp - (difff % 0x100000000) + 0x100000000) % 0x100000000;
    return static_cast<uint32_t>(temp);
    //return static_cast<uint32_t>(system_clock::to_time_t(system_clock::now()));
}

int get_my_id() {
    std::string str = execute("ifconfig | grep mesh0 | awk '{print $5}' | tr 'A-Z' 'a-z'");
    str.pop_back();
    for(int i = 0; i < mac_table.size(); ++i) {
        if(str.compare(mac_table[i])==0) {
            #ifdef _YY_DEBUG_PRINT_
                ofs << "my board id is " << (i+1) << endl;
            #endif
            ip_table[i] = "127.0.0.1";
            return (i+1);
        }
    }
    return 0;        //invalid
}

const uint16_t basic_crc_table[] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7, 
    0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF, 
    0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6, 
    0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE, 
    0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485, 
    0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D, 
    0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4, 
    0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC, 
    0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823, 
    0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B, 
    0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12, 
    0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A, 
    0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41, 
    0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49, 
    0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70, 
    0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78, 
    0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F, 
    0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067, 
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E, 
    0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256, 
    0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D, 
    0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405, 
    0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C, 
    0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634, 
    0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB, 
    0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3, 
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A, 
    0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92, 
    0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9, 
    0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1, 
    0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8, 
    0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0,
};

void refresh_route_table() {
    for(int i = 20; i < 25; ++i) {    //没事闲的就先扫一遍子网
        execute("ping 192.168.43." + to_string(i) + " -W 1 -c 1");
    }
    int my_id = get_my_id();
    for(int i = 0; i < mac_table.size(); ++i) {
        if(i!= my_id - 1) {    //get ip from arp cache
            std::string ip_i = execute("arp -nv | grep ether | grep " + mac_table[i] + "| awk '{print $2}' | tr -d '()'");
            if(ip_i.size() <= 3) {        //干, 网络里这个鬼板子压根儿没存在过
                ip_table[i] = "";    
                mac_connect[i] = false;
            } else {                    //不是空串
                //determine whether can connect
                ip_i.pop_back();ip_table[i] = ip_i;    //多个回车, 烦人, 删了开心
                std::string pingresult = execute("ping " + ip_i + " -W 1 -c 1 | grep '100% packet loss'");
                mac_connect[i] = pingresult.empty();//是否能ping通
            }    
        }    
    }
    mesh_info[0] = my_id;     mesh_info[2] = 1;    mesh_info[4] = 2;     mesh_info[6] = 3;
    for(int i = 0; i < mac_table.size(); ++i) {
        if(i == my_id - 1) {
            mesh_info[2*i+3] = 1;
        } else {
            std::string result = execute("iw dev mesh0 mpath dump | grep mesh0 | awk '$1==\"+mac_table[i] + \"{print$2}'");
            result.pop_back();
            if(result.compare(mac_table[0])==0) {
                mesh_info[2*i+3] = 1;
            } else if(result.compare(mac_table[1])==0) {
                mesh_info[2*i+3] = 2;
            } else if(result.compare(mac_table[2])==0) {
                mesh_info[2*i+3] = 3;
            } else if(result.compare("38:d2:69:d1:1b:23")==0) {    //dhcp host
                mesh_info[2*i+3] = (my_id==2?(i+1):2);
            } else {
                mesh_info[2*i+3] = 0;                            //fuck
            }
        }
    }
}

uint16_t get_crc_code(uint8_t* data, uint32_t length) {
    uint16_t code = 0xFFFF;
    for(uint32_t i = 0; i < length; ++i) {
        code = ((code << 8) ^ basic_crc_table[(((code >> 8) ^*data++) & 0xFF)]);
    }
    return code;
}

uint16_t my_port = 0x0001;        //我们的无线网卡端口
uint16_t mc_port = 0x0002;        //主控端端口(main_control)
uint8_t  my_node_num = 0x00;    //本机节点号

const uint16_t FRAME_HEAD = 0xEB90;
const uint16_t EOM = 0xA55A;
uint8_t first_byte = 0x00;
//打包spa消息
std::vector<uint8_t> package_spa_message(uint16_t target_port, const uint8_t* data, int n, uint16_t message_code) {
    
    std::vector<uint8_t> msg(19+n);    //创建一个长度是(19+n) Byte的动态数组
    msg[0] = first_byte;
    //帧头
    msg[1] = FRAME_HEAD >> 8;
    msg[2] = FRAME_HEAD & 0xFF;
    //长度
    int length = n + 14; //in Byte
    msg[3] = length >> 8;
    msg[4] = length & 0xFF;
    //时间戳
    uint32_t time_stamp = get_system_time();
    msg[5] = (time_stamp >> 24) & 0xFF;
    msg[6] = (time_stamp >> 16) & 0xFF;
    msg[7] = (time_stamp >>  8) & 0xFF;
    msg[8] =  time_stamp & 0xFF;
    //源地址
    msg[9] = my_port & 0xFF;
    msg[10] = my_port >> 8;
    //目的地址
    msg[11] = target_port & 0xFF;
    msg[12] = target_port >> 8;

    //消息码
    msg[13] = message_code >> 8;
    msg[14] = message_code & 0xFF;
    //复制消息数据
    const uint8_t* j = data;
    uint8_t* k = &msg[15];
    for(int i = 0; i < n; ++i) {
        *k = *j;
        ++k; ++j;
    }
    
    //CRC校验, 从帧头开始, 到消息数据结束(CRC之前)
    uint16_t cksum = 0xFFFF;
    for(int i = 1; i < 15; ++i)
        cksum = basic_crc_table[((cksum>>8) ^ msg[i]) & 0xff] ^ (cksum << 8);
    for(int i = 0; i < n; ++i)
        cksum = basic_crc_table[((cksum>>8) ^ *data++) & 0xff] ^ (cksum << 8);
    msg[n+15] = cksum >> 8;
    msg[n+16] = cksum & 0xFF;
    
    //消息结束符EOM
    msg[n+17] = EOM >> 8;
    msg[n+18] = EOM & 0xFF;
    
    return msg;
}

using SPA_MSG = std::vector<uint8_t> ;
//读取消息
uint16_t get_length(const SPA_MSG& msg) {                            //取长度
    return (msg[3] << 8) + msg[4] - 14;
}
uint32_t get_time_stamp(const SPA_MSG& msg) {                        //取时间戳
    return (msg[5] << 24) | (msg[6] << 16) | (msg[7] << 8) | msg[8];
}
uint16_t get_source_port(const SPA_MSG& msg) {                    //取源地址
    return (msg[10] << 8) | msg[9];
}
uint16_t get_target_port(const SPA_MSG& msg) {                    //取目的地址
    return (msg[12] << 8) | msg[11];
}
uint16_t get_message_code(const SPA_MSG& msg) {                    //取消息码
    return (msg[13] << 8) | msg[14];
}

//todo:向FPGA发送消息
int temp0913 = 0;
void send_to_fpga(const SPA_MSG& msg) {
    temp0913 = (temp0913+1) % 10;
    if(temp0913 != 0)
        return;
    #ifdef _YY_DEBUG_PRINT_ 
        ofs << "sending data to FPGA: ";
        ofs << (int)(mc_port & 0xFF) << ", ";
        for(auto item: msg)
            ofs << "0x" << setw(2) << setfill('0') << (int)item << ", ";
        ofs << "EOP" << endl;
    #endif

    *(gpmc_write_base_addr) = mc_port & 0xFF; //发主控端端口
    for(auto item: msg) {
        *(gpmc_write_base_addr) = item;
    }
    *(gpmc_write_base_addr) = 0x0100;
    *(gpmc_write_base_addr) = 0x0100;

}


void send_route_to_host() { //通过串口发送给主机
    refresh_route_table();        //读取route
    ofs.put('\n');
    ofs.put('E').put('B').put('9').put('1').put('E').put('B').put('9').put('1');
    char write = 0;
    for(auto elem: mesh_info) {
        write = (char) (((elem >> 4) & 0xF) + 'a');    //传4个bit
        ofs.put(write);
        write = (char) ((elem & 0xF) + 'a');//再传4个bit
        ofs.put(write);
    }
    ofs.put('\n').flush();
}


void send_mechanics_param_to_host(
    int user,                         //user 1 or user 3
    const vector<double>& data1,    //27个double参数
    const vector<int>& data2        //3个int参数
    ) {
    ofs.put('\n');
    ofs.put('E').put('B').put('9').put('1').put('E').put('B').put('9').put('1');
    char write;
    write = (char)(user + 'a');
    ofs.put(write);
    
    int size1 = data1.size();        //应该是27才对
    int size2 = data2.size();        //应该是3才对

    double valDouble = 0;
    for(int i = 0; i < size1; ++i) {
        valDouble = data1[i];
        uint64_t bitsDoubleValue = *(reinterpret_cast<uint64_t*>(&valDouble));
        for(int j = 0; j < 16; ++j) {            
            write = (char)(((bitsDoubleValue >> (60-j*4)) & 0xF) +'a');
            ofs.put(write);
        }
    }

    int valint = 0;    
    for(int i = 0; i < size2; ++i) {
        valint = data2[i];
        uint32_t bitsIntValue = *(reinterpret_cast<uint32_t*>(&valint));
        for(int j = 0; j < 8; ++j) {            
            write = (char)(((bitsIntValue >> (28-j*4)) & 0xF)+'a');
            ofs.put(write);
        }
    }
    ofs.put('\n').flush();
}

SPA_MSG msg_buf;

void send_A502() {        //发送 寻的消息ACK 至主控端
    uint8_t ackdata[] {
        0x88, 0xFF    //(端口类型, 服务类型列表...)
    };
    SPA_MSG msg = package_spa_message(mc_port, ackdata, 2, 0xA502);
    send_to_fpga(msg);
}


void handle_A501(const SPA_MSG& msg) {    //处理寻的消息
    static int A501_cnt = 0;
    ++A501_cnt;
    //对时
    clocking(get_time_stamp(msg));
    //对主控端端口
    mc_port = get_source_port(msg);
    //对自己的端口
    my_port = get_target_port(msg);
    if(A501_cnt % 10 == 0)        //每10次回一个寻的消息
        send_A502();
}

void send_A504() {        //发送回数消息(路由信息) 至FPGA
    refresh_route_table();
    SPA_MSG msg = package_spa_message(mc_port, mesh_info.data(), mesh_info.size(), 0xA504);
    send_to_fpga(msg);
}

inline void handle_A503() {    //处理取数消息
    send_A504();
}

void handle_A602(const SPA_MSG& msg) {    //处理星间消息
    uint8_t node_num = msg[14];
    #ifdef _YY_DEBUG_PRINT_
        ofs << "处理星间消息, 准备发给" << node_num << endl;
    #endif
    if(node_num>mac_table.size() || (!mac_connect[node_num-1]))
        return;
    const uint8_t* data = msg.data() + 16;
    //将A602中的 [端口号, 原始数据一并传递到wifi]
    int n = get_length(msg) - 2;
    //todo: send to wifi (data, n)
    send_addr_1.sin_addr.s_addr = inet_addr(ip_table[node_num-1].c_str());
    SduFlagPack_0.sdu_length = n;
    ++SduFlagPack_0.sdu_sn;

    uint8_t* read_buffer = SduFlagPack_0.data;
    for(int i = 0; i < n; ++i) {
        *read_buffer++ = *data++;
    }
    int num1=sendto(send_socket_1,&SduFlagPack_0,21+SduFlagPack_0.sdu_length,0,(struct sockaddr*)&send_addr_1,sizeof(send_addr_1));
}

//处理从FPGA接收到的消息
inline void handle_fpga(const SPA_MSG& msg) {
    first_byte = msg[0];
    uint16_t message_code = get_message_code(msg);
    if(message_code == 0xA501) {            //如果是寻的消息
        handle_A501(msg);
    } else if(message_code == 0xA503) {        //如果是取数消息
        handle_A503();
    } else if(message_code == 0xA602) {        //如果是星间数据消息
        handle_A602(msg);
    } else {
        ;    //do nothing
    }
}

//接收一次并处理从wifi收到的消息(发0xA601)
inline void handle_wifi() {
    int num2=recvfrom(recv_socket_1, &SduFlagPack_1, sizeof(SduFlagPack),
                        0,(struct sockaddr*)&send_addr_2,&send_addr_2_size);
    if(num2 == -1)
        return;            
    if(SduFlagPack_1.Flag==($XY)) {            //收到的数据有效
        int N = SduFlagPack_1.sdu_length;
        printf("Data Received, Length = %d(*8 bit)\n", N-4);
        //未完成: Todo: 区分给FPGA的包和显示包, 若是显示包, 就调用send_mechanics_param_to_host发给串口
        const uint8_t* data_ptr = SduFlagPack_1.data;
        uint16_t len = (uint16_t)(N/2+2);
        uint16_t target_port = *data_ptr++;
        SPA_MSG msg = package_spa_message(target_port, data_ptr, len - 1, 0xA601);
        send_to_fpga(msg);
    }
}

void sigint_handler(int sig) {
    if(sig == SIGINT) {
        try {
            ofs << "\nreceiving ctrl+C, exiting....." << endl;
            yy_gpmc_free(); ofs.close(); 
        } catch(exception e) {
            cerr << "艹, sigint_handler引发了异常: "<< e.what() << endl;
        }
        exit(sig);
    }
}

int main() {
    signal(SIGINT, sigint_handler);
    //用于打印到串口
    ofs.open("/dev/ttyS0", ios::out | ios::app);
    yy_gpmc_init(); yy_socket_init();
    
    uint16_t read_data;
    auto timeStart = system_clock::now();
    while(true) {
        
        read_data = *gpmc_read_base_addr;
        if((read_data & 0x0200) && (read_data!=0xFFFF)) {
            if(read_data & 0x0100) {
                #ifdef _YY_DEBUG_PRINT_
                    ofs << "EOP" << endl;
                #endif
                if(msg_buf.size()>=3) {
                    if(msg_buf[0]==0x00) {
                        msg_buf.erase(msg_buf.begin(), msg_buf.begin() + 1);
                    }
                    handle_fpga(msg_buf);
                    #ifdef _YY_DEBUG_PRINT_
                        ofs << "received from FPGA: ";
                        for(auto item: msg_buf)
                            ofs << (int)item << ", ";
                        ofs << endl;
                    #endif
                }        
                msg_buf.clear();
            } else {
                msg_buf.push_back(read_data & 0xFF);
                #ifdef _YY_DEBUG_PRINT_
                    ofs << "0x" << setw(2) << setfill('0') << (int)(read_data & 0xFF) << ", ";
                #endif
            }
        } else { //我猜此时gpmc应该是空闲的
            auto timeInterval = duration_cast<std::chrono::milliseconds>(system_clock::now() -timeStart);
            if(timeInterval.count() > 2000) {    //2秒
                handle_wifi();
                send_route_to_host();
                timeStart = system_clock::now();
            }
        }
    }

    ofs.close();
    yy_gpmc_free();

    return 0;
}
