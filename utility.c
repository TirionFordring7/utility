/*─────────────────────────────────────────────────────────────────────────────
 *  utility.c – отправить ICMPv4 Echo Request и вывести MAC-адрес Echo Reply
 *───────────────────────────────────────────────────────────────────────────*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <poll.h>

/*--------------------------------------------------------------------------*/
/** @brief   16-битная «internet checksum» (RFC 1071).
 *  @param   data   Буфер, по которому считается сумма.
 *  @param   len    Длина буфера в байтах.
 *  @return  Готовая контрольная сумма в сетевом порядке байт.               */
static uint16_t csum16(const void *data, size_t len)
{
    const uint16_t *w = data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *w++;
        len -= 2;
    }
    if (len) sum += *(const uint8_t *)w;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}

/*--------------------------------------------------------------------------*/
/** @brief  Формирование ICMP Echo Request фиксированного размера.
 *  @param  buf   Буфер не меньше 64 байт (8 байт заголовок + 56 байт данных).
 *  @param  id    Идентификатор ICMP.
 *  @param  seq   Порядковый номер.
 *  @return Длину пакета либо −1 при ошибке.                            */
static ssize_t build_icmp_echo(uint8_t *buf, uint16_t id, uint16_t seq)
{
    const size_t pkt_len = 64;
    if (!buf) return -1;

    struct icmphdr *icmp = (struct icmphdr *)buf;
    icmp->type     = ICMP_ECHO;
    icmp->code     = 0;
    icmp->checksum = 0;
    icmp->un.echo.id       = htons(id);
    icmp->un.echo.sequence = htons(seq);

    size_t data_len = pkt_len - sizeof(struct icmphdr);
    memset(buf + sizeof(struct icmphdr), 0, data_len);
    time_t now = time(NULL);
    memcpy(buf + sizeof(struct icmphdr), &now,
           (data_len < sizeof(now)) ? data_len : sizeof(now));

    icmp->checksum = csum16(buf, pkt_len);
    return pkt_len;
}

/*--------------------------------------------------------------------------*/
/** @brief  Отправить ICMP-пакет через SOCK_RAW (AF_INET, IPPROTO_ICMP).
 *  @param  sock     Открытый сокет.
 *  @param  dst      IPv4-адрес назначения.
 *  @param  pkt      Указатель на ICMP-кадр.
 *  @param  len      Длина кадра в байтах.
 *  @return 0 — успех, −1 — ошибка.                                 */
static int send_icmp(int sock, struct in_addr dst,
                     const uint8_t *pkt, size_t len)
{
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_addr   = dst
    };
    ssize_t w = sendto(sock, pkt, len, 0,
                       (struct sockaddr *)&sa, sizeof(sa));
    if (w != (ssize_t)len) {
        perror("sendto");
        return -1;
    }
    return 0;
}

/*--------------------------------------------------------------------------*/
/** @brief  Открыть пакетный сокет (AF_PACKET, ETH_P_ALL)
 *  @return fd ≥ 0 либо −1.                                                  */
static int open_packet_socket()
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket(AF_PACKET)"); return -1; }
    return fd;
}

/*--------------------------------------------------------------------------*/
/** @brief  Ожидать ICMP Echo Reply и вернуть MAC-адрес отправителя.
 *  @param  psock   AF_PACKET-сокет.
 *  @param  id    Ожидаемые значения ICMP id.
 *  @param  seq   Ожидаемые значения ICMP seq.
 *  @param  tout_ms Тайм-аут ожидания, мс.
 *  @param  mac_out Массив для результата.
 *  @return 0 — успех, −1 — тайм-аут/ошибка.              */
static int wait_reply(int psock, uint16_t id, uint16_t seq,
                      int tout_ms, uint8_t mac_out[ETH_ALEN])
{
    uint8_t buf[2048];
    struct pollfd pfd = { .fd = psock, .events = POLLIN };

    while (poll(&pfd, 1, tout_ms) > 0) {
        ssize_t n = recv(psock, buf, sizeof(buf), 0);
        if (n < (ssize_t)(sizeof(struct ether_header) +
                          sizeof(struct iphdr) +
                          sizeof(struct icmphdr)))
            continue;

        
        struct ether_header *eth = (struct ether_header *)buf;
        if (ntohs(eth->ether_type) != ETH_P_IP) continue;

        
        struct iphdr *ip = (struct iphdr *)(buf + sizeof(struct ether_header));
        size_t ip_hl = ip->ihl * 4;
        if (ip_hl < 20) continue;
        if (ip->protocol != IPPROTO_ICMP) continue;

        
        struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(struct ether_header) + ip_hl);
        if (icmp->type != ICMP_ECHOREPLY || icmp->code != 0) continue;
        if (icmp->un.echo.id       != htons(id))  continue;
        if (icmp->un.echo.sequence != htons(seq)) continue;

        memcpy(mac_out, eth->ether_shost, ETH_ALEN);
        return 0;
    }
    return -1;  
}

/*--------------------------------------------------------------------------*/
/** @brief  Вывод MAC-адреса в формате xx:xx:xx:xx:xx:xx.
 *  @param  m Массив для MAC-адреса.
 *  @return void.
 */
static void print_mac(const uint8_t m[ETH_ALEN])
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
           m[0], m[1], m[2], m[3], m[4], m[5]);
}


int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <IPv4-address>\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "Need root (CAP_NET_RAW)\n");
        return EXIT_FAILURE;
    }

    struct in_addr dst_ip;
    if (inet_pton(AF_INET, argv[1], &dst_ip) != 1) {
        perror("inet_pton");
        return EXIT_FAILURE;
    }

    // Формировка ICMP-пакета 
    uint8_t icmp_pkt[64];
    uint16_t pid16 = (uint16_t)getpid();
    if (build_icmp_echo(icmp_pkt, pid16, 1) < 0) {
        fprintf(stderr, "build_icmp_echo failed\n");
        return EXIT_FAILURE;
    }

    // Создание сокетов 
    int s_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s_icmp < 0) { perror("socket raw icmp"); return EXIT_FAILURE; }

    int s_pkt = open_packet_socket();
    if (s_pkt < 0) { close(s_icmp); return EXIT_FAILURE; }

    // Отправка запроса 
    if (send_icmp(s_icmp, dst_ip, icmp_pkt, sizeof(icmp_pkt)) < 0) {
        close(s_icmp); close(s_pkt); return EXIT_FAILURE;
    }

    // Ожидание ответа и вывод MAC-адреса 
    uint8_t mac[ETH_ALEN];
    if (wait_reply(s_pkt, pid16, 1, 3000, mac) == 0) {
        print_mac(mac);
        close(s_icmp); close(s_pkt);
        return EXIT_SUCCESS;
    } else {
        fprintf(stderr, "Timeout waiting for Echo Reply\n");
        close(s_icmp); close(s_pkt);
        return EXIT_FAILURE;
    }
}
