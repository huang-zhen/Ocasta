/*
 * Sample program that makes gconf calls
 */
/*
 * Copyright (C) 2016 Zhen Huang
 */

#define GCONF_ENABLE_INTERNALS

#include <gconf/gconf-client.h>
#include <gconf/gconf.h>
 
  #define APPLICATION_NAME "sample"
  #define GCONF_DIR "/apps/gconf-sample/"
 
  /**
   * Store an integer key "mykey" with a specified value to gconf database
   */ 
  static void StoreMykey( gint value ) {  
    GConfClient* gconfClient = gconf_client_get_default();
    g_assert(GCONF_IS_CLIENT(gconfClient));
 
    if(!gconf_client_set_int(gconfClient, GCONF_DIR "mykey", value, NULL)) {
      g_warning(" failed to set %smykey (%d)\n", GCONF_DIR, value);
    }
 
    /* release GConf client */
    g_object_unref(gconfClient);
  }
 
  /**
   * Get an integer value from key "mykey"
   */ 
  static void GetMykey( gint* value ) {  
    GConfClient* gconfClient = gconf_client_get_default();
    g_assert(GCONF_IS_CLIENT(gconfClient));
 
    GConfValue* gcValue = NULL;    
    gcValue = gconf_client_get_without_default(gconfClient, GCONF_DIR "mykey", NULL);
 
    /* if value pointer remains NULL, the key was not found */
    if(gcValue == NULL) {
      g_warning(" key %smykey not found\n", GCONF_DIR);
      g_object_unref(gconfClient);
      return;
    }
 
    /* Check if value type is integer */
    if(gcValue->type == GCONF_VALUE_INT) {
      *value = gconf_value_get_int(gcValue);
    }
    else {
      g_warning(" key %smykey is not integer\n", GCONF_DIR);
    }
 
    /* Release resources */
    gconf_value_free(gcValue);
    g_object_unref(gconfClient);
  }

int main() {
int value;

printf("gconf version:%s\n", gconf_version);
StoreMykey(100);
GetMykey(&value);
if (value == 100)
	printf("Test of gconf_value_get_int and gconf_client_set_int succeeded\n");
else
	printf("Test of gconf_value_get_int and gconf_client_set_int failed\n");
return 0;
}

