//
//  rjpeg.c
//  otus-c-2021-09
//
//  Created by a.pulichkin on 22.10.2021.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/stat.h>

#define LFH_SIGNATURE 0x04034b50
#define CDFH_SIGNATURE 0x02014b50
#define EOCDR_SIGNATURE 0x06054b50
#define CDFH_BASE_SIZE 46  //base size for cdfh
#define EOCDR_BASE_SIZE 22 //base size for eocdr
#define LFH_BASE_SIZE 30


// Local file headers
#pragma pack(push, 1)
struct LFH {
    uint32_t signature;                 /* The signature of the local file header. This is always '\x50\x4b\x03\x04'. */
    uint16_t version;                   /* PKZip version needed to extract */
    uint16_t flags;                     /* General purpose bit flag: 00–15 */
    uint16_t compression_method;        /* bit flag: 00-19, 98 */
    uint16_t file_modification_time;    /* stored in standard MS-DOS format Bits 00-04: seconds divided by 2 Bits 05-10: minute Bits 11-15: hour*/
    uint16_t file_modification_date;    /* stored in standard MS-DOS format */
    uint32_t crc_32_checksum;           /* value computed over file data by CRC-32 algorithm with 'magic number' 0xdebb20e3 (little endian) */
    uint32_t compressed_size;           /* if archive is in ZIP64 format, this filed is 0xffffffff and the length is stored in the extra field */
    uint32_t uncompressed_size;         /* if archive is in ZIP64 format, this filed is 0xffffffff and the length is stored in the extra field */
    uint16_t file_name_length;          /* The length of the file name field below. */
    uint16_t extra_field_length;        /* The length of the extra field below. */
};
#pragma pack(pop)


// Central directory file header
#pragma pack(push, 1)
struct CDFH {
    uint32_t signature;                 /* The signature of the file header. This is always '\x50\x4b\x01\x02'. */
    uint16_t version;                   /* Version made by upper byte: 0-20 */
    uint16_t version_needed;            /* PKZip version needed to extract */
    uint16_t flags;                     /* General purpose bit flag: 00–15 */
    uint16_t compression_method;        /* bit flag: 00-19, 98 */
    uint16_t file_modification_time;    /* stored in standard MS-DOS format */
    uint16_t file_modification_date;    /* stored in standard MS-DOS format */
    uint32_t crc_32_checksum;           /* value computed over file data by CRC-32 algorithm with 'magic number' 0xdebb20e3 (little endian)  */
    uint32_t compressed_size;           /* if archive is in ZIP64 format, this filed is 0xffffffff and the length is stored in the extra field */
    uint32_t uncompressed_size;         /* if archive is in ZIP64 format, this filed is 0xffffffff and the length is stored in the extra field */
    uint16_t file_name_length;          /* The length of the file name field below. */
    uint16_t extra_field_length;        /* The length of the extra field below. */
    uint16_t file_comm_len;             /* the length of the file comment */
    uint16_t disk_start;                /* The number of the disk on which this file exists */
    uint32_t internal_attr;             /* Internal file attributes Bit 0–16*/
    uint32_t external_attr;             /* External file attributes: host-system dependent*/
    uint32_t offset_of_local_header;    /* Relative offset of local header. Offset of where to find the corresponding local file header from the start of the first disk.*/
};
#pragma pack(pop)

// End of central directory record
#pragma pack(push, 1)
struct EOCDR {
    uint32_t signature;                 /* The signature of end of central directory record. This is always '\x50\x4b\x05\x06'. */
    uint16_t disk_number;               /* The number of this disk (containing the end of central directory record). */
    uint16_t disk_cd;                   /* Number of the disk on which the central directory starts. */
    uint16_t disk_entries;              /* The number of central directory entries on this disk */
    uint16_t total_entries;             /* Total number of entries in the central directory. */
    uint32_t central_directory_size;    /* Size of the central directory in bytes. */
    uint32_t offset_of_cd;              /* Offset of the start of the central directory on the disk on which the central directory starts. */
    uint16_t comment_length;            /* The length of the following comment field. */
};
#pragma pack(pop)


static int find_eocdr(struct EOCDR *, uint8_t *, size_t);
static int find_cdfh(uint8_t *, size_t *);
static int find_lfh(uint8_t *, size_t *);
static int iterate_entries(struct EOCDR *eocdr, uint8_t *src, size_t entries, size_t filesize);
static void calculate_offset(size_t, size_t, size_t, size_t *, size_t *);
static uint8_t* read_file(const char *, size_t *);


int main(int argc, char *argv[]){
    if (argc < 2) {
        perror ("Please, enter the path of the zip file!");
        return -1;
    }

    const char* filename = argv[1];
    struct EOCDR eocdr;
    size_t filesize;
    uint8_t *rawdata = read_file(filename, &filesize);
    
    if (!find_eocdr(&eocdr, rawdata, filesize)) {
        perror("ERROR while searching end of central directory record. This is not a zip file");
        return 0;
    }
    
    //iterarte over zip
    iterate_entries(&eocdr, rawdata, eocdr.disk_entries, filesize);
    
    //free buffer from read_file
    free(rawdata);
    
    return 0;
}


static int find_eocdr(struct EOCDR *eocdr, uint8_t *src, size_t src_len)
{
    size_t oecdr_offset = src_len - sizeof(struct EOCDR);

    while (oecdr_offset <= src_len) {
        memcpy(eocdr, &src[oecdr_offset], sizeof(struct EOCDR));
        if (eocdr->signature == EOCDR_SIGNATURE) {
            printf("---------------------------------\n");
            printf("Found contents:\n");
            return 1;
        }
        oecdr_offset++;
    }

    return 0;
}

static void calculate_offset(size_t central_directory_size, size_t offset_of_cd, size_t filesize, size_t *offset, size_t *offset_lh){
    size_t x, offset_cd, size_cd;
    
    size_cd = central_directory_size;
    offset_cd = offset_of_cd;
    x = filesize - EOCDR_BASE_SIZE - size_cd; // 22 – base size for eocdr
    *offset = x;
    *offset_lh = x - offset_cd;
}

static int find_cdfh(uint8_t *src, size_t *offset){
    struct CDFH cdfh;
    memcpy(&cdfh, &src[*offset], CDFH_BASE_SIZE);
    if (cdfh.signature != CDFH_SIGNATURE) {
        return 0;
    }
    
    *offset += CDFH_BASE_SIZE + cdfh.file_name_length \
                            + cdfh.extra_field_length \
                            + cdfh.file_comm_len;
    return 1;
}

static int find_lfh(uint8_t *src, size_t *offset_lh){
    struct LFH lfh;
    int is_lfh = 0;
    while(!is_lfh){
        memcpy(&lfh, &src[*offset_lh], LFH_BASE_SIZE);
        if (lfh.signature == LFH_SIGNATURE) {
            printf("---------------------------------\n");
            char filename[lfh.file_name_length];
            memset(filename, '\0', lfh.file_name_length + 1);
            memcpy(filename, &src[*offset_lh + LFH_BASE_SIZE], lfh.file_name_length);
            printf("File -> %s\n", filename);
            is_lfh = 1;
        }
        *offset_lh += 1;
    }
    if(!is_lfh){
        return 0;
    }
    return 1;
}

static int iterate_entries(struct EOCDR *eocdr, uint8_t *src, size_t entries, size_t filesize){
    size_t offset, offset_lh;
    
    //calculate offset for first central directory file header
    calculate_offset(eocdr->central_directory_size, eocdr->offset_of_cd, filesize, &offset, &offset_lh);
    
    /* Read the member info. */
    for (size_t i = 0; i < entries; ++i) {
        if (!find_cdfh(src, &offset)) {
            perror("ERROR to read central directory file header");
            return 0;
        }
        if (!find_lfh(src, &offset_lh)) {
            perror("ERROR to read local file header");
            return 0;
        }
    }
    return 1;
}

static uint8_t* read_file(const char *filename, size_t *file_size){
    FILE *fp;
    uint8_t *bufer;
    struct stat sb;
    
    if (stat(filename, &sb) == -1) {
            perror("stat");
            exit(EXIT_FAILURE);
        }

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    
    *file_size = sb.st_size;
    bufer = malloc(*file_size);
    
    if (bufer == NULL) {
        perror("malloc bufer");
        exit(EXIT_FAILURE);
    }
    
    while (feof(fp) == 0) {
        fread(bufer, *file_size, 1, fp);
        if (ferror(fp)) {
            perror("fread fp");
            exit(EXIT_FAILURE);
        }
    }

    if (fclose(fp)) {
        perror("fclose fp");
        exit(EXIT_FAILURE);
    }
    
    fclose(fp);
    return bufer;
}

