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
  while (fgets(path, sizeof(path), fp) != NULL) {
//    printf("%s", path);
  }
  pclose(fp);

  if(path[0] == '1') {
//    printf("[pam_sm_acct_mgmt] Headphones connected\n");
    return PAM_SUCCESS;
  } else {
//    printf("[pam_sm_acct_mgmt] Headphones not connected\n");
    return PAM_AUTH_ERR;
  }
}

/*
 * get_device_id
 *
 * Reads the first device identifier from ZIA config file
 *
 */
static void get_device_id(char *user, char *line, int size) {
  char dev_id_file_path[500];
  strcpy(dev_id_file_path, "/Users/");
  strcat(dev_id_file_path, user);
  strcat(dev_id_file_path, "/.zia/devices");
  FILE *f = fopen(dev_id_file_path, "r");
  while(fgets(line, size, f) != NULL) {
    if(line[strlen(line)-1] == '\n') {
      line[strlen(line)-1] = '\0';
    }
//    printf("Read \"%s\"\n", line);
    fclose(f);
    return;
  }
}

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  int retval;
//  printf("Acct mgmt\n");
  char devid[64];

  const char* pUsername;
  retval = pam_get_user(pamh, &pUsername, "Username: ");
  get_device_id((char*)pUsername, devid, sizeof(devid));
  
  retval = check_device_connected(devid);

//  printf("pam_sm_acct_mgmt returning %d\n", retval);

  return retval;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
  int retval;
  char devid[64];

  const char* pUsername;
  retval = pam_get_user(pamh, &pUsername, "Username: ");

//  printf("Welcome %s\n", pUsername);

  if (retval != PAM_SUCCESS) {
      return retval;
  }

  get_device_id((char*)pUsername, devid, sizeof(devid));
  
  retval = check_device_connected(devid);

//  printf("pam_sm_authenticate returning %d\n", retval);

  return retval;
}
