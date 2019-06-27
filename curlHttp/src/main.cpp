// A very simple example of how HTTPDownloader is supposed to be used

#include <iostream>
#include <sstream>

#include "HttpDownloader.hpp"
#ifdef WINDOWS
    #include <direct.h>
    #define GetCurrentDir _getcwd
#else
    #include <unistd.h>
    #define GetCurrentDir getcwd
 #endif


int main(int argc, const char * argv[]) {
    char cCurrentPath[FILENAME_MAX];
    GetCurrentDir(cCurrentPath, sizeof(cCurrentPath));
    std::string path = cCurrentPath;
    std::string urlPath = argv[1];
    std::string fileName(urlPath.substr(urlPath.rfind("/")));
    path+= fileName;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    HTTPDownloader downloader;
    std::stringstream contents;
    
    
    if (argc < 2) {
        std::cout << "Pass the URI on the command line" << std::endl;
        return 1;
    }
    
    try
    {
        // char outfilename[FILENAME_MAX] = "C:\\Users\\Trenton Rochelle\\Coding\\Summer2019\\PQC_DownloadManager\\HttpDownloader-master\\test.pdf";
        // FILE *fp = fopen(outfilename,"wb");
        // downloader.download(contents, std::string{argv[1]}, "text/html; charset=utf-8", 300000);
        downloader.download(contents, std::string{argv[1]}, "application/pdf", 300000,0,path);

    }
    catch (const HTTPDownloaderException& e)
    {
        std::cout << e.what() << std::endl;
        return 1;
    }
    
    // std::cout << contents.str() << std::endl;
    // JSON.parse(contents.str());
    curl_global_cleanup();
    
    return 0;
}
