/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/* <DESC>
 * Download many files in parallel, in the same thread.
 * </DESC>
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#  include <unistd.h>
#endif
#include <curl/curl.h>
#include <iostream>
#include <sstream>
#include <functional>
#include <memory>
#include <iosfwd>
#include <fstream>
#include <map>
#include <algorithm>
#include <cstdio>
#include <sys/stat.h>
#define GetCurrentDir getcwd

static const char *urls[] = {
  "https://www.microsoft.com",
  "https://opensource.org",
  "https://www.google.com",
  "https://www.yahoo.com",
  "https://www.ibm.com",
  "https://www.mysql.com",
  "https://www.oracle.com",
  "https://www.ripe.net",
  "https://www.iana.org",
  "https://www.amazon.com",
  "https://www.netcraft.com",
  "https://www.heise.de",
  "https://www.chip.de",
  "https://www.ca.com",
  "https://www.cnet.com",
  "https://www.mozilla.org",
  "https://www.cnn.com",
  "https://www.wikipedia.org",
  "https://www.dell.com",
  "https://www.hp.com",
  "https://www.cert.org",
  "https://www.mit.edu",
  "https://www.nist.gov",
  "https://www.ebay.com",
  "https://www.playstation.com",
  "https://www.uefa.com",
  "https://www.ieee.org",
  "https://www.apple.com",
  "https://www.symantec.com",
  "https://www.zdnet.com",
  "https://www.fujitsu.com/global/",
  "https://www.supermicro.com",
  "https://www.hotmail.com",
  "https://www.ietf.org",
  "https://www.bbc.co.uk",
  "https://news.google.com",
  "https://www.foxnews.com",
  "https://www.msn.com",
  "https://www.wired.com",
  "https://www.sky.com",
  "https://www.usatoday.com",
  "https://www.cbs.com",
  "https://www.nbc.com",
  "https://slashdot.org",
  "https://www.informationweek.com",
  "https://apache.org",
  "https://www.un.org",
  "https://sites.cs.ucsb.edu/~yfwang/courses/cs281b/homework_old/prog1.pdf",
};

#define MAX_PARALLEL 10 /* number of simultaneous transfers */
#define NUM_URLS sizeof(urls)/sizeof(char *)

std::string path;
std::map<const char*,FILE*> urlToFP; //key:url, value:file pointer

/**
 * Write callback for writefunction in curl_easy_setopt .... I think I removed this
 * @param
 * @return 
 */

static size_t write_cb(char *data, size_t n, size_t l, void *userp)
{
  /* take care of the data here, ignored in this example */
  (void)data;
  (void)userp;
  return n*l;
}


/**
 * Takes a url and creates a temp file in the download folder
 * @param char * of the original url for cURL to download
 * @return filePath of the temp file
 */
static std::string urlToFilePath(const char * url_charstar){ 
  std::string url(url_charstar);
  std::replace( url.begin(), url.end(), '/', '-');
  std::string filePath = path + "/downloads/" + url.substr(8) + ".temp";
  return filePath;
}


/**
 * Adds a download to the curl multi handler (allows multiple non-blocking downloads at once)
 * Creates a temporary file which will be renamed once download is finished
 * @param cURL multi, urls index number to grab the desired url
 * @return None
 */

static void add_transfer(CURLM *cm, int i)
{

  std::string filePath = urlToFilePath(urls[i]);
  FILE *fp;
  fp = fopen(filePath.c_str(),"wb"); //create temp file from filePath

  urlToFP.insert(std::pair<const char*, FILE*>(urls[i],fp)); //inserts mapping from url to file pointer

  CURL *eh = curl_easy_init();
  // curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, NULL);
  curl_easy_setopt(eh, CURLOPT_URL, urls[i]);
  curl_easy_setopt(eh, CURLOPT_PRIVATE, urls[i]);
  curl_easy_setopt(eh, CURLOPT_WRITEDATA, fp);
  curl_easy_setopt(eh, CURLOPT_FOLLOWLOCATION, 1L);
  
  curl_multi_add_handle(cm, eh);
}


/**
 * Sets the path variable to the current run path
 * @param None
 * @return None
 */
static void setPath(){
  char cCurrentPath[FILENAME_MAX];
  GetCurrentDir(cCurrentPath, sizeof(cCurrentPath));
  path = cCurrentPath;
}

inline bool fileExists (const std::string& name) {
  struct stat buffer;   
  return (stat (name.c_str(), &buffer) == 0); 
}

int main(void)
{

  setPath();

  CURLM *cm;
  CURLMsg *msg;
  unsigned int transfers = 0;
  int msgs_left = -1;
  int still_alive = 1;

  curl_global_init(CURL_GLOBAL_ALL);
  cm = curl_multi_init();

  /* Limit the amount of simultaneous connections curl should allow: */
  curl_multi_setopt(cm, CURLMOPT_MAXCONNECTS, (long)MAX_PARALLEL);

  for(transfers = 0; transfers < MAX_PARALLEL; transfers++)
    add_transfer(cm, transfers);

  do {
    curl_multi_perform(cm, &still_alive);

    while((msg = curl_multi_info_read(cm, &msgs_left))) {
      if(msg->msg == CURLMSG_DONE) {
        char *url;
        CURL *e = msg->easy_handle;
        curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &url);
        fclose(urlToFP.find(url)->second); //closes file
        urlToFP.erase(urlToFP.find(url)); //removes url/filePointer pair

        char *ct;
        curl_easy_getinfo(msg->easy_handle, CURLINFO_CONTENT_TYPE, &ct);
        std::string extension(ct);
        extension = extension.substr(0, extension.find(';'));
        extension = extension.substr(extension.find('/')+1);
        // std::cout << "We received Content-Type: " << extension << "\n";


        char *redir_url = NULL;
        curl_easy_getinfo(msg->easy_handle, CURLINFO_EFFECTIVE_URL, &redir_url); //gets the final redirected url


        std::string oldFilePath = urlToFilePath(url);
        std::string::iterator it = oldFilePath.end()-4;
        std::string newFilePath = oldFilePath.substr(0, it-oldFilePath.begin())+extension;
        if (fileExists(newFilePath)){
          std::cout << "File with that name " << newFilePath << "already exists! Rename the temp file yourself :)\n";
        }
        else{
          if (std::rename(oldFilePath.c_str(), newFilePath.c_str())) {
            std::perror("Error renaming");
            return 1;
          }
        }


        fprintf(stderr, "R: %d - %s <%s>\n",
                msg->data.result, curl_easy_strerror(msg->data.result), url);
        curl_multi_remove_handle(cm, e);
        curl_easy_cleanup(e);
      }
      else {
        fprintf(stderr, "E: CURLMsg (%d)\n", msg->msg);
      }
      if(transfers < NUM_URLS)
        add_transfer(cm, transfers++);
    }
    if(still_alive)
      curl_multi_wait(cm, NULL, 0, 1000, NULL);

  } while(still_alive || (transfers < NUM_URLS));

  curl_multi_cleanup(cm);
  curl_global_cleanup();

  return EXIT_SUCCESS;
}