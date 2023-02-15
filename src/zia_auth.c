/*
 * zia_auth.c
 *
 * Neil Klingensmith
 * 2-13-2023
 *
 * Copyright 2023 ZIA Labs
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <unistd.h>
#include <curl/curl.h>



char curl_output_buf[10];

/*
 * config_read_param
 *
 * Reads a configuration parameter from a config file.
 *
 * Inputs:
 *
 *   path: the path of the config file to read from
 *   param: the name of the parameter to read
 *   value: a buffer to place the value of the configuration parameter
 *   n: the length of value in bytes
 *
 * Outputs:
 *   Returns 0 and populates value with the value of the config parameter on
 *   success. Returns -1 if it can't find the config file.
 */
static int config_read_param(char *path, char *param, char *value, int n) {
  FILE *f = fopen(path, "r");
  int ret = -1;
  char line[1024];// Temp buf to store line contents

  // Read config file one line at a time
  while(fgets(line, sizeof(line), f) != NULL) {
    // Remove the newline character from the end of the line
    if(line[strlen(line)-1] == '\n') {
      line[strlen(line)-1] = '\0';
    }
    char *token = strtok(line, " \t");

    if((token != NULL) && (strcmp(token, "#") == 0)) {
      // Found a comment
      continue;
    }
    // Compare the config param name to the one the user is looking for
    if((token != NULL) && (strcmp(token, param) == 0)) {
      // Found a config param that matches!!
      token = strtok(NULL," \t");
      strncpy(value, token, n);
      ret = 0;
      break;
    }
  }
  fclose(f);
  return ret;
}


/*
 * check_device_connected
 *
 * Calls blueutil to find out if a particular device is connected. Returns
 * PAM_SUCCESS if device is connected, otherwise returns PAM_AUTH_ERR.
 *
 */
static int check_device_connected(char *devid) {
  // Run `blueutil --is-connected` to find out if neil's headphones are connected
  FILE *fp;
  char path[1035];

  /* Open the command for reading. */
  fp = popen("BLUEUTIL_ALLOW_ROOT=1 blueutil --is-connected  08-ff-44-07-92-4e", "r");
  if (fp == NULL) {
    printf("ZIA PAM Module: Failed to run blueutil\n");
    return PAM_AUTH_ERR;
  }

  /* Read the output a line at a time - output it. */
  while (fgets(path, sizeof(path), fp) != NULL);

  pclose(fp);

  if(path[0] == '1') {
    return PAM_SUCCESS;
  } else {
    return PAM_AUTH_ERR;
  }
}

/*
 * get_api_creds
 *
 * Reads the the user's API username and password from config file
 *
 */
static int get_api_creds(char *user, char *api_user, int api_user_size, char *api_key, int api_key_size) {
  char config_file_path[500];
  strcpy(config_file_path, "/Users/");
  strcat(config_file_path, user);
  strcat(config_file_path, "/.zia/config");

 
  if( config_read_param(config_file_path, "APIUsername", api_user, api_user_size) < 0 ) {
    return PAM_AUTH_ERR;
  }
  if( config_read_param(config_file_path, "APIKey", api_key, api_key_size) ) {
    return PAM_AUTH_ERR;
  }
  return PAM_SUCCESS;
}
/*
 * get_device_id
 *
 * Reads the first device identifier from ZIA config file
 *
 */
static void get_device_id(char *user, char *line, int size) {
  char config_file_path[500];
  strcpy(config_file_path, "/Users/");
  strcat(config_file_path, user);
  strcat(config_file_path, "/.zia/config");

  config_read_param(config_file_path, "DeviceID", line, size);
}

static size_t curl_recv_callback(void *data, size_t size, size_t nmemb, void *clientp){
//  printf("[curl_recv_callback] got %ld bytes of data\n", size * nmemb);

  // Copy no more than sizeof(curl_output_buf) bytes into curl_output_buf
  size_t n = size * nmemb > sizeof(curl_output_buf) ? sizeof(curl_output_buf) : size * nmemb;
  memcpy(curl_output_buf, data, n);

  return size*nmemb;
}

/*
 * api_log
 *
 * Log an authentication with the ZIA Labs API
 *
 */
static int api_log(char *user) {
  CURL *curl;
  CURLcode res;
  char urlbuf[1024];
  char api_username[1024];
  char api_key[64];

  // Read the user's API credentials from the config file
  if(get_api_creds(user, api_username, sizeof(api_username), api_key, sizeof(api_key)) < 0) {
    printf("ERROR: no API credentials set in ~/.zia/config. See documentation on https://zialabs.co.\n");
    return PAM_AUTH_ERR;
  }

  curl_global_init(CURL_GLOBAL_DEFAULT);
 
  curl = curl_easy_init();
  if(curl) {
    // Construct the URL to the ZIA Labs API from the user's API username and API key
    strcpy(urlbuf, "https://zialabs.co/api/v0/usr/");
    strcat(urlbuf, api_username);
    strcat(urlbuf, "/");
    strcat(urlbuf, api_key);
    strcat(urlbuf, "/logauth");

    curl_easy_setopt(curl, CURLOPT_URL, urlbuf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_recv_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)curl_output_buf);
    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    } else {
    }
//    printf("[api_log] complete curl_output_buf = \"%s\"\n", curl_output_buf);
    /* always cleanup */
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  // curl_output_buf has the data that came back from the API. If the API
  // returns '1', then the authentication succeeds. Otherwise it fails.
  if((strlen(curl_output_buf) > 0) && curl_output_buf[0] == '1') {
    return PAM_SUCCESS;
  } else {
    return PAM_AUTH_ERR;
  }

}

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  int retval;
  char devid[64];

  const char* pUsername;
  retval = pam_get_user(pamh, &pUsername, "Username: ");
  get_device_id((char*)pUsername, devid, sizeof(devid));
  
  if(api_log((char*)pUsername) != 0) { // Log authentication to ZIA Labs servers
    // If API log fails, return error. This can happen if user has an invalid account
    retval = PAM_AUTH_ERR;
  } else {
    // If API log succeeds
    retval = check_device_connected(devid);
  }
  return retval;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
  int retval;
  char devid[64];

  const char* pUsername;
  retval = pam_get_user(pamh, &pUsername, "Username: ");

  if (retval != PAM_SUCCESS) {
      return retval;
  }

  get_device_id((char*)pUsername, devid, sizeof(devid));


  if(api_log((char*)pUsername) != 0) { // Log authentication to ZIA Labs servers
    // If API log fails, return error. This can happen if user has an invalid account
    retval = PAM_AUTH_ERR;
  } else {
    // If API log succeeds
    retval = check_device_connected(devid);
  }

  return retval;
}
