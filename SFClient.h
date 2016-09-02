#ifndef SFCLIENT_H
#define SFCLIENT_H

#include <ArduinoJson.h>
#include "Client.h"

static const char* DEFAULT_HOST_LOGIN = "login.salesforce.com";
static const char* DEFAULT_HOST_INSTANCE = "na35.salesforce.com";
static const int DEFAULT_PORT = 443;
static const char* ENDPOINT_TOKEN = "/services/oauth2/token";
static const char* ENDPOINT_SOBJECTS = "/services/data/v37.0/sobjects/";

class SFClient
{
  public:
    SFClient(Client* client,
              const char* clientId,
              const char* clientSecret,
              const char* securityToken,
              const char* hostLogin = DEFAULT_HOST_LOGIN,
              const char* hostInstance = DEFAULT_HOST_INSTANCE,
              int port = DEFAULT_PORT);

    int connect(void);
    int authenticate(const char* username, const char* password);
    int createRecord(const char* sObjectName, JsonObject& object);

  private:
    Client* _client;
    const char* _clientId;
    const char* _clientSecret;
    const char* _securityToken;
    String _accessToken;
    const char* _username;
    const char* _password;
    const char* _hostLogin;
    const char* _hostInstance;
    int _port;

    int initSettings(String resp);
    String getHttpCode(String resp);
};

#endif
