//
//  rjpeg.c
//  otus-c-2021-09
//
//  Created by a.pulichkin on 22.10.2021.
//

#include <stdio.h>
#include <stdlib.h>

#define LFH_SIGNATURE 0x04034b50
#define CDFH_SIGNATURE 0x02014b50
#define EOCDR_SIGNATURE 0x06054b50
#define CDFH_BASE_SIZE 46  //base size for cdfh
#define EOCDR_BASE_SIZE 22 //base size for eocdr


// Local file headers
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
    const uint8_t *file_name;           /* the name of the file including an optional relative path. All slashes in the path should be forward slashes '/'. */
    const uint8_t *extra_field;         /* Used to store additional information.
                                        The field consistes of a sequence of header and data pairs,
                                        where the header has a 2 byte identifier and a 2 byte data size field.. */
};


// Central directory file header
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
    const uint8_t *file_name;           /* the name of the file including an optional relative path. All slashes in the path should be forward slashes '/'.*/
    const uint8_t *extra_field;         /* Used to store additional information. The field consistes of a sequence of header and data pairs,
                                           where the header has a 2 byte identifier and a 2 byte data size field. */
    const uint8_t *file_comment;        /* An optional comment for the file.*/
};


// End of central directory record
struct EOCDR {
    uint32_t signature;                 /* The signature of end of central directory record. This is always '\x50\x4b\x05\x06'. */
    uint16_t disk_number;               /* The number of this disk (containing the end of central directory record). */
    uint16_t disk_cd;                   /* Number of the disk on which the central directory starts. */
    uint16_t disk_entries;              /* The number of central directory entries on this disk */
    uint16_t total_entries;             /* Total number of entries in the central directory. */
    uint32_t central_directory_size;    /* Size of the central directory in bytes. */
    uint32_t offset_of_cd;              /* Offset of the start of the central directory on the disk on which the central directory starts. */
    uint16_t comment_length;            /* The length of the following comment field. */
    const uint8_t *zip_file_comment;    /* Optional comment for the Zip file. */
};


static int find_eocdr(struct EOCDR *, uint8_t *, size_t);
static int read_cdfh(struct CDFH *, uint8_t *, size_t);
static int read_lfh(struct LFH *lfh, uint8_t *, size_t);
static uint8_t* read_file(const char *, size_t *);
static uint16_t read16(unsigned char **);
static uint32_t read32(unsigned char **);


static uint16_t read16(unsigned char **p){
    uint16_t res;
    uint8_t *tmp;
    
    tmp = *p + 1;
    res = (*tmp << 8) | **p;
    *p +=2;
    return res;
}

static uint32_t read32(unsigned char **p){
    uint32_t res=0;
    uint8_t *tmp;
    
    for(int i=3;i>=0;i--){
        tmp = *p + i;
        res = res | (*tmp << i*8);
    }
    *p+=4;
    return res;
}

static int read_lfh(struct LFH *lfh, uint8_t *src, size_t offset){
    uint8_t *p;
    uint32_t signature;

    p = &src[offset];
    signature = read32(&p);
    if (signature != LFH_SIGNATURE) {
        perror("LFH signature not found!");
        return 0;
    }
    lfh->signature = signature;
    lfh->version = read16(&p);
    lfh->flags = read16(&p);
    lfh->compression_method = read16(&p);
    lfh->file_modification_time = read16(&p);
    lfh->file_modification_date = read16(&p);
    lfh->crc_32_checksum = read32(&p);
    lfh->compressed_size = read32(&p);
    lfh->uncompressed_size = read32(&p);
    lfh->file_name_length = read16(&p);
    lfh->extra_field_length = read16(&p);
    p[lfh->file_name_length] = 0; // remove UT from filename
    lfh->file_name = p;
    lfh->extra_field = lfh->file_name + lfh->file_name_length;
    printf("%s\n", lfh->file_name);
    return 1;
}

static int read_cdfh(struct CDFH *cdfh, uint8_t *src, size_t offset)
{
    uint8_t *p;
    uint32_t signature;
    
    p = &src[offset];
    signature = read32(&p);
    if (signature != CDFH_SIGNATURE) {
        perror("CDFH signature not found!");
        return 0;
    }
    cdfh->signature = signature;
    cdfh->version = read16(&p);
    cdfh->version_needed = read16(&p);
    cdfh->flags = read16(&p);
    cdfh->compression_method = read16(&p);
    cdfh->file_modification_time = read16(&p);
    cdfh->file_modification_date = read16(&p);
    cdfh->crc_32_checksum = read32(&p);
    cdfh->compressed_size = read32(&p);
    cdfh->uncompressed_size = read32(&p);
    cdfh->file_name_length = read16(&p);
    cdfh->extra_field_length = read16(&p);
    cdfh->file_comm_len = read16(&p);
    cdfh->disk_start = read16(&p);
    cdfh->internal_attr = read16(&p);
    cdfh->external_attr = read32(&p);
    cdfh->offset_of_local_header = read32(&p);
    cdfh->file_name = p;
    cdfh->extra_field = cdfh->file_name + cdfh->file_name_length;
    cdfh->file_comment = cdfh->extra_field + cdfh->extra_field_length;

    return 1;
}


static int find_eocdr(struct EOCDR *r, uint8_t *src, size_t src_len)
{
    uint8_t *p;
    uint32_t signature;
    size_t oecdr_offset = src_len - sizeof(struct EOCDR);

    for (; oecdr_offset <= src_len; oecdr_offset++) {
        p = &src[oecdr_offset];
        signature = read32(&p);
        if (signature == EOCDR_SIGNATURE) {
            r->signature = signature;
            r->disk_number = read16(&p);
            r->disk_cd = read16(&p);
            r->disk_entries = read16(&p);
            r->total_entries = read16(&p);
            r->central_directory_size = read32(&p);
            r->offset_of_cd = read32(&p);
            r->comment_length = read16(&p);
            r->zip_file_comment = p;
            return 1;
        }
    }

    return 0;
}

static uint8_t* read_file(const char *filename, size_t *file_size){
    FILE *fp;
    uint8_t *bufer;
    size_t bufer_size;

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    bufer_size = 4096;
    bufer = malloc(bufer_size);
    if (bufer == NULL) {
        perror("malloc bufer");
        exit(EXIT_FAILURE);
    }

    *file_size = 0;
    while (feof(fp) == 0) {
        if (bufer_size - *file_size == 0) {
            bufer_size *= 2;
            bufer = realloc(bufer, bufer_size);
            if (bufer == NULL) {
                perror("realloc bufer");
                exit(EXIT_FAILURE);
            }
        }

        *file_size += fread(&bufer[*file_size], 1, bufer_size - *file_size, fp);
        if (ferror(fp)) {
            perror("fread fp");
            exit(EXIT_FAILURE);
        }
            
    }

    if (fclose(fp)) {
        perror("fclose fp");
        exit(EXIT_FAILURE);
    }
    return bufer;
}

int main(int argc, char *argv[]){
//    if (argc < 2) {
//        perror ("Please, enter the path of the zip file!");
//        return -1;
//    }
//
//    const char* filename = argv[1];
    const char* filename = "/Users/a.pulichkin/Documents/C_Projects/otus/03_types_homework-12926-a575e3/zipjpeg.jpg";
    struct EOCDR eocdr;
    struct CDFH cdfh;
    struct LFH lfh;
    uint8_t *rawdata;
    size_t filesize, i, x, offset, offset_cd, size_cd, concat, file_offset;
    
    rawdata = read_file(filename, &filesize);
    if (!find_eocdr(&eocdr, rawdata, filesize)) {
        perror("ERROR while searching end of central directory record. This is not a zip file");
        return 0;
    }
    //calculate offset for first central directory file header
    size_cd = eocdr.central_directory_size;
    offset_cd = eocdr.offset_of_cd;
    x = filesize - EOCDR_BASE_SIZE - size_cd; // 22 – base size for eocdr
    concat = x - offset_cd;
    offset = offset_cd + concat;
    /* Read the member info. */
    for (i = 0; i < eocdr.disk_entries; ++i) {
        if (!read_cdfh(&cdfh, rawdata, offset)) {
            perror("ERROR to read central directory file header");
            return 0;
        }
        //calculate offset for local file header
        file_offset = cdfh.offset_of_local_header + concat;
        if (!read_lfh(&lfh, rawdata, file_offset)) {
            printf("ERROR to read local file header");
            return 0;
        }
        //calculate offset for next central directory file header
        offset += CDFH_BASE_SIZE + cdfh.file_name_length \
                     + cdfh.extra_field_length \
                     + cdfh.file_comm_len;

    }
    
    return 0;
}
