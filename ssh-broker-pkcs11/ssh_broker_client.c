#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include "base64.h"
#include "ssh_broker_client.h"

RemoteKey* RemoteKey_new() {
    RemoteKey* rk = malloc(sizeof(RemoteKey));
    if (rk == NULL) {
        return NULL;
    }
    memset(rk, 0, sizeof(*rk));
    return rk;
}

void RemoteKey_free(RemoteKey* rk) {
    if (rk != NULL) {
        if (rk->key_name != NULL) {
            free(rk->key_name);
        }
        if (rk->public_key != NULL) {
            free(rk->public_key);
        }
        free(rk);
    }
}

ListKeysResponse* ListKeysResponse_new() {
    ListKeysResponse* lkr = malloc(sizeof(ListKeysResponse));
    if (lkr == NULL) {
        return NULL;
    }
    memset(lkr, 0, sizeof(*lkr));
    return lkr;
}

void ListKeysResponse_free(ListKeysResponse* lkr) {
    if (lkr != NULL) {
        for (unsigned long i = 0; i < lkr->keys_length; i++) {
            if (lkr->keys[i] != NULL) {
                RemoteKey_free(lkr->keys[i]);
            }
        }
        if (lkr->keys != NULL) {
            free(lkr->keys);
        }
        free(lkr);
    }
}

SignRequest* SignRequest_new() {
    SignRequest* sr = malloc(sizeof(SignRequest));
    if (sr == NULL) {
        return NULL;
    }
    memset(sr, 0, sizeof(*sr));
    return sr;
}

void SignRequest_free(SignRequest* sr) {
    if (sr != NULL) {
        if (sr->public_key != NULL) {
            free(sr->public_key);
        }
        if (sr->signature_algorithm != NULL) {
            free(sr->signature_algorithm);
        }
        if (sr->data != NULL) {
            free(sr->data);
        }
        free(sr);
    }
}

struct InputBuffer {
  const char* buffer;
  size_t length;
  size_t pos;
};

static size_t read_callback(void *data, size_t size, size_t nitems, void *userdata) {
  struct InputBuffer* buffer = (struct InputBuffer*)userdata;
  size_t to_read = size * nitems;
  if (to_read > buffer->length - buffer->pos) {
    to_read = buffer->length - buffer->pos;
  }
  memcpy(data, buffer->buffer + buffer->pos, to_read);
  buffer->pos += to_read;
  return to_read;
}

struct OutputBuffer {
   char* buffer;
   size_t size;
};

static size_t write_callback(void *data, size_t size, size_t nitems, void *userdata) {
  struct OutputBuffer* buffer = (struct OutputBuffer*)userdata;
  size_t to_read = size * nitems;

  char *ptr = realloc(buffer->buffer, buffer->size + to_read);
  if(ptr == NULL) {
    return 0;
  }

  buffer->buffer = ptr;
  memcpy(&(buffer->buffer[buffer->size]), data, to_read);
  buffer->size += to_read;
  return to_read;
}

static struct json_object* do_rest_request(const char* url, struct json_object* input) {
  struct curl_slist *list = NULL;
  CURL *curl = NULL;
  CURLcode res;
  struct InputBuffer input_buffer;
  struct OutputBuffer output_buffer;
  struct json_object* output = NULL;

  curl = curl_easy_init();
  if (curl == NULL) {
    return NULL;
  }

  input_buffer.buffer = json_object_to_json_string(input);
  input_buffer.length = strlen(input_buffer.buffer);
  input_buffer.pos = 0;
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
  curl_easy_setopt(curl, CURLOPT_READDATA, (void *)&input_buffer);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, input_buffer.length);

  output_buffer.buffer = NULL;
  output_buffer.size = 0;
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&output_buffer);

  list = curl_slist_append(list, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
  // FIXME: Prefix hostname/port and just accept path as param
  curl_easy_setopt(curl, CURLOPT_URL, url);
  //curl_easy_setopt(curl, CURLOPT_CAINFO, "FIXME");
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  // FIXME: Support client cert
  res = curl_easy_perform(curl);
  if (res == CURLE_OK) {
    struct json_tokener* tok = json_tokener_new();
    output = json_tokener_parse_ex(tok, output_buffer.buffer, output_buffer.size);
    json_tokener_free(tok);
  }

  if (output_buffer.buffer != NULL) {
    free(output_buffer.buffer);
  }
  if (list != NULL) {
    curl_slist_free_all(list);
  }
  if (curl != NULL) {
    curl_easy_cleanup(curl);
  }
  return output;
}

ListKeysResponse* list_keys() {
  struct json_object* req = json_object_new_object();
  struct json_object* res = do_rest_request("https://localhost:7002/REST/v1/listKeys", req);
  json_object_put(req);

  ListKeysResponse* output = NULL;
  if (res != NULL) {
    output = ListKeysResponse_new();
    if (json_object_is_type(res, json_type_object)) {
      struct json_object* keys;
      if (json_object_object_get_ex(res, "keys", &keys) && json_object_is_type(keys, json_type_array)) {
        size_t keys_length = json_object_array_length(keys);
        output->keys = malloc(sizeof(RemoteKey) * keys_length);
        if (output->keys == NULL) {
          ListKeysResponse_free(output);
          json_object_put(res);
          return NULL;
        }
        output->keys_length = keys_length;

        for (size_t idx = 0; idx < keys_length; idx++) {
          struct json_object* key = json_object_array_get_idx(keys, idx);
          if (json_object_is_type(key, json_type_object)) {
            struct json_object *key_name, *public_key;
            output->keys[idx] = RemoteKey_new();
            if (output->keys[idx] == NULL) {
              ListKeysResponse_free(output);
              json_object_put(res);
              return NULL;
            }

            if (json_object_object_get_ex(key, "keyName", &key_name) && json_object_is_type(key_name, json_type_string)) {
              output->keys[idx]->key_name = strdup(json_object_get_string(key_name));
            }
            if (json_object_object_get_ex(key, "publicKey", &public_key) && json_object_is_type(key_name, json_type_string)) {
              output->keys[idx]->public_key = base64_decode(json_object_get_string(public_key), &output->keys[idx]->public_key_length);
            }
          }
        }
      }
    }

    json_object_put(res);
  }

  return output;
}

void ssh_broker_sign(const unsigned char* public_key, size_t public_key_length,
                     const unsigned char* dgst, size_t dgst_length,
                     unsigned char** pOutSignature, size_t* pOutSignatureLength) {

  struct json_object* req = json_object_new_object();
  char* public_key_b64 = base64_encode(public_key, public_key_length);
  json_object_object_add(req, "publicKey", json_object_new_string(public_key_b64));
  free(public_key_b64);
  json_object_object_add(req, "signatureAlgorithm", json_object_new_string("SHA256withECDSA"));

  char* dgst_b64 = base64_encode(dgst, dgst_length);
  json_object_object_add(req, "data", json_object_new_string(dgst_b64));
  free(dgst_b64);
  json_object_object_add(req, "isDigested", json_object_new_boolean(TRUE));

  struct json_object* res = do_rest_request("https://localhost:7002/REST/v1/sign", req);
  json_object_put(req);

  *pOutSignature = NULL;
  *pOutSignatureLength = 0;
  if (res != NULL) {

    struct json_object* sigObj;
    if (json_object_object_get_ex(res, "signature", &sigObj) && json_object_is_type(sigObj, json_type_string)) {
      *pOutSignature = base64_decode(json_object_get_string(sigObj), pOutSignatureLength);
    }
    json_object_put(res);
  }
}
