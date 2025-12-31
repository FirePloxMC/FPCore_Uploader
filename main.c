#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "wininet.lib")

#define API_HOST "control.sparkedhost.us"
#define BUFFER_SIZE 8192

char API_KEY[256] = {0};
char WEBHOOK_URL[512] = {0};

int load_api_key(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) return 0;

    if (fgets(API_KEY, sizeof(API_KEY), file) == NULL) {
        fclose(file);
        return 0;
    }

    size_t len = strlen(API_KEY);
    if (len > 0 && API_KEY[len - 1] == '\n') {
        API_KEY[len - 1] = '\0';
    }

    fclose(file);
    return 1;
}

int load_webhook_url(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) return 0;

    if (fgets(WEBHOOK_URL, sizeof(WEBHOOK_URL), file) == NULL) {
        fclose(file);
        return 0;
    }

    size_t len = strlen(WEBHOOK_URL);
    if (len > 0 && WEBHOOK_URL[len - 1] == '\n') {
        WEBHOOK_URL[len - 1] = '\0';
    }

    fclose(file);
    return 1;
}

const char *SERVER_NAMES[] = {
    "Survival",
    "Hub", 
    "Creative",
    "Skyblock",
    "Dev"
};

const char *SERVERS[] = {
    "12dd4fb5", // Survival
    "6832f0c5", // Hub
    "8249e2c3", // Creative
    "1aaaaf14", // Skyblock
    "f51dad67" // Dev server
};
const int SERVER_COUNT = 5; 

#define DEFAULT_FILE ".\\target\\FPCore-1.0.jar"
#define DEFAULT_DIR "/plugins"

// Send Discord webhook notification
void send_discord_webhook(int success, const char *server_name) {
    if (strlen(WEBHOOK_URL) == 0) return;

    const char *path_start = strstr(WEBHOOK_URL, "discord.com");
    if (!path_start) return;
    path_start += strlen("discord.com");

    char webhook_path[512];
    strncpy(webhook_path, path_start, sizeof(webhook_path) - 1);
    webhook_path[sizeof(webhook_path) - 1] = '\0';

    HINTERNET hInternet = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    char json_payload[512];
    if (success) {
        snprintf(json_payload, sizeof(json_payload), 
            "{\"content\":\"FPCore successfully pushed to **%s**\"}", server_name);
    } else {
        snprintf(json_payload, sizeof(json_payload), 
            "{\"content\":\"FPCore failed to push to **%s**\"}", server_name);
    }

    hInternet = InternetOpenA("FPCoreUploader/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return;

    hConnect = InternetConnectA(hInternet, "discord.com", INTERNET_DEFAULT_HTTPS_PORT,
                                 NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return;
    }

    DWORD flags = INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD;
    hRequest = HttpOpenRequestA(hConnect, "POST", webhook_path, NULL, NULL, NULL, flags, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }

    const char* headers = "Content-Type: application/json\r\n";
    HttpSendRequestA(hRequest, headers, (DWORD)strlen(headers),
                     json_payload, (DWORD)strlen(json_payload));

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
}

// Make HTTP request using WinINet - older version
char *http_request(const char *host, const char *path, int port, int secure, const char *method, const char *headers, const char *body, DWORD body_len) {
    HINTERNET hInternet = InternetOpenA("FPCoreUploader/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return NULL;

    HINTERNET hConnect = InternetConnectA(hInternet, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return NULL;
    }

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if (secure) {
        flags |= INTERNET_FLAG_SECURE;
    }

    HINTERNET hRequest = HttpOpenRequestA(hConnect, method, path, NULL, NULL, NULL, flags, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return NULL;
    }

    if (secure) {
        DWORD dwFlags;
        DWORD dwBuffLen = sizeof(dwFlags);
        InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, &dwBuffLen);
        dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }

    BOOL result;
    if (body && body_len > 0) {
        result = HttpSendRequestA(hRequest, headers, headers ? -1L : 0, (LPVOID)body, body_len);
    } else {
        result = HttpSendRequestA(hRequest, headers, headers ? -1L : 0, NULL, 0);
    }

    if (!result) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return NULL;
    }

    char *response = malloc(BUFFER_SIZE);
    if (!response) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return NULL;
    }

    DWORD bytesRead = 0;
    DWORD totalBytesRead = 0;

    while (InternetReadFile(hRequest, response + totalBytesRead, BUFFER_SIZE - totalBytesRead - 1, &bytesRead) && bytesRead > 0) {
        totalBytesRead += bytesRead;
        if (totalBytesRead >= BUFFER_SIZE - 1) break;
    }

    response[totalBytesRead] = '\0';

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return response;
}

// Extract upload URL from JSON response and unescape it
char *extract_upload_url(const char *json) {
    const char *url_key = "\"url\":\"";
    char *url_start = strstr(json, url_key);
    
    if (!url_start) return NULL;
    
    url_start += strlen(url_key);
    char *url_end = strchr(url_start, '"');
    
    if (!url_end) return NULL;
    
    size_t url_length = url_end - url_start;
    char *url = malloc(url_length + 1);
    if (!url) return NULL;
    
    // UNESCAPE THE FUCKING BACKSLASHES
    char *dst = url;
    const char *src = url_start;
    while (src < url_end) {
        if (*src == '\\' && *(src + 1) == '/') {
            *dst++ = '/';
            src += 2;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
    
    return url;
}

// Parse URL into components
typedef struct {
    char host[256];
    char path[2048];
    int port;
    int secure;
} ParsedURL;

int parse_url(const char *url, ParsedURL *parsed) {
    parsed->secure = (strncmp(url, "https://", 8) == 0);
    parsed->port = parsed->secure ? 443 : 80;
    
    const char *host_start = url + (parsed->secure ? 8 : 7);
    const char *port_start = strchr(host_start, ':');
    const char *path_start = strchr(host_start, '/');
    
    if (!path_start) return 0;
    
    if (port_start && port_start < path_start) {
        strncpy(parsed->host, host_start, port_start - host_start);
        parsed->host[port_start - host_start] = '\0';
        parsed->port = atoi(port_start + 1);
    } else {
        strncpy(parsed->host, host_start, path_start - host_start);
        parsed->host[path_start - host_start] = '\0';
    }
    
    strcpy(parsed->path, path_start);
    
    return 1;
}

// Get upload URL from API
char *get_upload_url(const char *server_uuid, const char *directory) {
    char path[512];
    sprintf(path, "/api/client/servers/%s/files/upload", server_uuid);
    
    char headers[1024];
    sprintf(headers, "Authorization: Bearer %s\r\nAccept: application/json\r\nContent-Type: application/json", API_KEY);
    
    char *response = http_request(API_HOST, path, 443, 1, "GET", headers, NULL, 0);
    
    if (!response) {
        printf("    Error: No response from API\n");
        return NULL;
    }
    
    // DEBUG print response if it looks like an error
    if (strstr(response, "error") || strstr(response, "Error") || !strstr(response, "url")) {
        printf("    API Response: %s\n", response);
    }
    
    char *url = extract_upload_url(response);
    free(response);
    
    if (url && directory && strlen(directory) > 0) {
        char *full_url = malloc(strlen(url) + strlen(directory) + 32);
        if (full_url) {
            sprintf(full_url, "%s&directory=%s", url, directory);
            free(url);
            return full_url;
        }
    }
    
    return url;
}

// Read file into memory
char *read_file(const char *filepath, DWORD *size) {
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    
    *size = GetFileSize(hFile, NULL);
    char *data = malloc(*size);
    
    if (data) {
        DWORD bytesRead;
        ReadFile(hFile, data, *size, &bytesRead, NULL);
    }
    
    CloseHandle(hFile);
    return data;
}

const char *get_filename(const char *path) {
    const char *name = strrchr(path, '\\');
    if (!name) name = strrchr(path, '/');
    return name ? name + 1 : path;
}

int upload_file(const char *upload_url, const char *filepath, const char *file_data, DWORD file_size) {
    ParsedURL parsed;
    if (!parse_url(upload_url, &parsed)) {
        printf("    Error: Failed to parse upload URL\n");
        return 0;
    }
    
    printf("    URL: %s\n", upload_url);
    printf("    Host: %s, Port: %d, Secure: %d\n", parsed.host, parsed.port, parsed.secure);
    printf("    Path: %s\n", parsed.path);
    
    const char *filename = get_filename(filepath);
    const char *boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    
    char header_part[512];
    sprintf(header_part,
            "--%s\r\n"
            "Content-Disposition: form-data; name=\"files\"; filename=\"%s\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n",
            boundary, filename);
    
    char footer_part[64];
    sprintf(footer_part, "\r\n--%s--\r\n", boundary);
    
    DWORD body_size = (DWORD)(strlen(header_part) + file_size + strlen(footer_part));
    char *body = malloc(body_size);
    if (!body) {
        printf("    Error: Failed to allocate memory\n");
        return 0;
    }
    
    memcpy(body, header_part, strlen(header_part));
    memcpy(body + strlen(header_part), file_data, file_size);
    memcpy(body + strlen(header_part) + file_size, footer_part, strlen(footer_part));
    
    char headers[256];
    sprintf(headers, "Content-Type: multipart/form-data; boundary=%s", boundary);
    
    HINTERNET hInternet = InternetOpenA("FPCoreUploader/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        printf("    Error: InternetOpen failed (%lu)\n", GetLastError());
        free(body);
        return 0;
    }

    HINTERNET hConnect = InternetConnectA(hInternet, parsed.host, parsed.port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        printf("    Error: InternetConnect failed (%lu)\n", GetLastError());
        InternetCloseHandle(hInternet);
        free(body);
        return 0;
    }

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if (parsed.secure) {
        flags |= INTERNET_FLAG_SECURE;
    }

    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", parsed.path, NULL, NULL, NULL, flags, 0);
    if (!hRequest) {
        printf("    Error: HttpOpenRequest failed (%lu)\n", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        free(body);
        return 0;
    }

    if (parsed.secure) {
        DWORD dwFlags;
        DWORD dwBuffLen = sizeof(dwFlags);
        InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, &dwBuffLen);
        dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }

    BOOL result = HttpSendRequestA(hRequest, headers, -1L, (LPVOID)body, body_size);
    free(body);
    
    if (!result) {
        printf("    Error: HttpSendRequest failed (%lu)\n", GetLastError());
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 0;
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusCodeSize, NULL);
    
    if (statusCode < 200 || statusCode >= 300) {
        printf("    HTTP Status: %lu\n", statusCode);
        
        char responseBody[1024] = {0};
        DWORD bytesRead = 0;
        InternetReadFile(hRequest, responseBody, sizeof(responseBody) - 1, &bytesRead);
        if (bytesRead > 0) {
            printf("    Response: %s\n", responseBody);
        }
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    
    return (statusCode >= 200 && statusCode < 300) ? 1 : 0;
}

int upload_to_server(const char *server_uuid, const char *server_name, const char *filepath, const char *file_data, DWORD file_size, const char *directory) {
    printf("  [%s] (%s)\n", server_name, server_uuid);
    printf("    Fetching upload URL...\n");
    
    char *upload_url = get_upload_url(server_uuid, directory);
    if (!upload_url) {
        printf("    Error: Failed to get upload URL\n");
        send_discord_webhook(0, server_name);
        return 0;
    }
    
    printf("    Uploading...\n");
    int result = upload_file(upload_url, filepath, file_data, file_size);
    free(upload_url);
    
    if (result) {
        printf("    Success!\n");
        send_discord_webhook(1, server_name);
    } else {
        printf("    Failed!\n");
        send_discord_webhook(0, server_name);
    }
    
    return result;
}

int main(int argc, char *argv[]) {
    const char *file_path = DEFAULT_FILE;
    const char *directory = DEFAULT_DIR;
    
    if (argc > 1) file_path = argv[1];
    if (argc > 2) directory = argv[2];
    
    if (!load_api_key("api_key.txt")) {
        printf("Error: Failed to load API key from api_key.txt\n");
        return 1;
    }
    
    if (strcmp(API_KEY, "YOUR_API_KEY_HERE") == 0) {
        printf("Error: Please set your API key in the source code\n");
        return 1;
    }

    if (!load_webhook_url("webhook.txt")) {
        printf("Warning: webhook.txt not found, Discord notifications disabled\n");
    }
    
    DWORD attrs = GetFileAttributesA(file_path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        printf("Error: File not found: %s\n", file_path);
        return 1;
    }
    
    DWORD file_size;
    char *file_data = read_file(file_path, &file_size);
    if (!file_data) {
        printf("Error: Cannot read file: %s\n", file_path);
        return 1;
    }
    
    printf("Uploading %s (%lu bytes) to %d server(s)...\n\n", get_filename(file_path), file_size, SERVER_COUNT);
    
    int success_count = 0;
    for (int i = 0; i < SERVER_COUNT; i++) {
        if (upload_to_server(SERVERS[i], SERVER_NAMES[i], file_path, file_data, file_size, directory)) {
            success_count++;
        }
        printf("\n");
    }
    
    free(file_data);
    
    printf("Done! %d/%d servers updated.\n", success_count, SERVER_COUNT);
    
    return (success_count == SERVER_COUNT) ? 0 : 1;
}