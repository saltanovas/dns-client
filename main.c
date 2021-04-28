#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <resolv.h>

#define DNS_SERVICE_PORT 53

#define RESCONF_PATH "/etc/resolv.conf"
#define MAXNS 3

#define DNS_MAX_DLNAME_LENGTH 63
#define DNS_MAX_PACKET_SIZE 512

#define DNS_TYPE_A 1
#define DNS_TYPE_CNAME 5 
#define DNS_TYPE_AAAA 28

#define DNS_CLASS_IN 1
#define DNS_CLASS_CS 2
#define DNS_CLASS_CH 3
#define DNS_CLASS_HS 4

typedef struct
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} DNS_HEADER;

typedef struct
{
    uint16_t qtype;
    uint16_t qclass;
} DNS_QUESTION;

typedef struct
{
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
} DNS_ANSWER;

int fpeek(FILE *stream)
{
    return ungetc(fgetc(stream), stream);
}

void ignore_comments(FILE *stream)
{
    while (fpeek(stream) == '#')
    {
        while (getc(stream) != '\n')
            continue;
    }
}

void read_conf(char **buffer, FILE *stream)
{
    char line[50];
    if (fgets(line, sizeof(line), stream) && strncmp(line, "nameserver", strlen("nameserver")) == 0)
    {
        strcpy(*buffer, strtok(line, "nameserver \n"));
    }
}

void get_dns_servers(char **str, int size)
{
    FILE *resolv_file = fopen(RESCONF_PATH, "rt");
    if (!resolv_file)
    {
        printf("Such file does not exist!\n");
        exit(1);
    }

    for (void *end = str + size + 1; str != end && fpeek(resolv_file) != EOF; ++str)
    {
        ignore_comments(resolv_file);
        read_conf(str, resolv_file);
    }

    fclose(resolv_file);
}

void encode_domain_name(char *src, char *dest)
{
    int count = 0;
    strcat(src, ".");
    for (void *end = src + strlen(src) + 1; src != end; ++src)
    {
        if (*src != '.')
        {
            ++count;
        }
        else
        {
            for (*dest++ = count; count != 0; --count)
            {
                *dest++ = *(src - count);
            }
        }
    }
    *dest = '\0';
}

void decode_domain_name(char *str)
{
    while (*str)
    {
        for (int len = *str; len != 0; --len, ++str)
        {
            *str = *(str + 1);
        }
        *str++ = '.';
    }
    *(--str) = '\0';
}

int init_client(unsigned short port_number, char *ip_address)
{
    int client_socket = 0;
    struct sockaddr_in server_address;

    if ((client_socket = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        fprintf(stderr, "Could not create a socket.\n\n");
        return -1;
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port_number);
    if (inet_pton(AF_INET, ip_address, &server_address.sin_addr) <= 0)
    {
        fprintf(stderr, "Failed to convert an ip address.\n\n");
        return -1;
    }

    if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) == -1)
    {
        fprintf(stderr, "Connection refused.\n\n");
        return -1;
    }
    else
    {
        printf("Successfully connected to %s:%d\n\n", inet_ntoa(server_address.sin_addr), ntohs(server_address.sin_port));
        return client_socket;
    }
}

void print_name(uint8_t *msg, uint8_t *str)
{
    char *a = calloc(strlen(str), sizeof(char));
    while (*str)
    {
        if (*str == 0xc0)
        {
            str = msg + ((*str & 0x3F) << 8) + *(str + 1);
        }
        else
        {
            putchar(*str++);
        }
    }
}

int main(int argc, char **argv)
{
    if(strlen(*(argv+1)) > DNS_MAX_DLNAME_LENGTH)
    {
        printf("Domain name is too long.");
        exit(1);
    }

    unsigned char qtype;
    if(strcmp(argv[2], "a") == 0)
    {
        qtype = DNS_TYPE_A;
    }
    else if(strcmp(argv[2], "aaaa") == 0)
    {
        qtype = DNS_TYPE_AAAA;
    }
    else
    {
        fprintf(stderr, "Unknown type '%s'. Use a or aaaa\n", argv[2]);
        exit(1);
    }


    char packet[DNS_MAX_PACKET_SIZE];
    int steps = 0;


    char **dns_addr = calloc(MAXNS, sizeof(char *));
    for (int i = 0; i < MAXNS; i++)
        *(dns_addr + i) = calloc(50, sizeof(char));
    get_dns_servers(dns_addr, MAXNS);


    DNS_HEADER *header = (DNS_HEADER *)&packet;
    header->id = htons(getpid());
    header->flags = htons(0x0100);
    header->qdcount = htons(1);
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;
    steps += sizeof(DNS_HEADER);


    encode_domain_name(*(argv+1), packet + steps);
    steps += (strlen(packet + steps) + 1);

    DNS_QUESTION *question = (DNS_QUESTION *)(packet + steps);
    question->qtype =  htons(qtype);
    question->qclass = htons(DNS_CLASS_IN);
    steps += sizeof(DNS_QUESTION);


    int sfd = init_client(DNS_SERVICE_PORT, *dns_addr);
    if (send(sfd, packet, steps, 0) < 0)
    {
        fprintf(stderr, "Send failed.");
        exit(1);
    }

    if (read(sfd, packet, DNS_MAX_PACKET_SIZE) < 0)
    {
        fprintf(stderr, "Read failed.");
        exit(1);
    }
    close(sfd);


    for (int i = 0; i < MAXNS; ++i)
    {
        free(*(dns_addr + i));
        *(dns_addr + i) = NULL;
    }
    free(dns_addr);
    dns_addr = NULL;


    switch (ntohs(header->flags) & 0x000F)
    {
    case 0:
        break;
    case 1:
        fprintf(stderr, "DNS Query Format Error.\n");
        exit(1);
    case 2:
        fprintf(stderr, "Server failed to complete the DNS request.\n");
        exit(1);
    case 3:
        fprintf(stderr, "Domain name does not exist.\n");
        exit(1);
    case 4:
        fprintf(stderr, "Function not implemented.\n");
        exit(1);
    case 5:
        fprintf(stderr, "The server refused to answer for the query.\n");
        exit(1);
    default:
        exit(1);
    }

    if(ntohs(header->ancount) == 0)
    {
        printf("No answers from the server.\n");
        exit(1);
    }

    decode_domain_name(packet + sizeof(DNS_HEADER));

    for (int i = 0; i < ntohs(header->ancount); ++i)
    {
        printf("NAME: ");
        print_name(packet, packet + steps);

        DNS_ANSWER *answer = (DNS_ANSWER *)(packet + steps + 2);
        steps += sizeof(DNS_ANSWER);

        switch (ntohs(answer->type))
        {
            case DNS_TYPE_A:
                printf("\tIPv4 address: %hhu.%hhu.%hhu.%hhu", packet[steps], packet[steps+1], packet[steps+2], packet[steps+3]);
            break;

            case DNS_TYPE_CNAME:
                printf("\tCNAME: ");
                print_name(packet, packet + steps);
            break;

            case DNS_TYPE_AAAA:
                printf("\tIPv6 address:%d ", ntohs(answer->rdlength));
                for (int i = 0; i < ntohs(answer->rdlength); i+=2)
                    printf("%02hhx%02hhx:", packet[steps+i], packet[steps+i+1]);
                printf("\b ");
                break;
        }

        steps += ntohs(answer->rdlength);
        putchar('\n');
    }

    return 0;
}
