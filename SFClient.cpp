#include "SFClient.h"

SFClient::SFClient(Client* client,
                  const char* clientId,
                  const char* clientSecret,
                  const char* securityToken,
                  const char* hostLogin,
                  const char* hostInstance,
                  int port)
{
  _client = client;
  _clientId = clientId;
  _clientSecret = clientSecret;
  _securityToken = securityToken;
  _hostLogin = hostLogin;
  _hostInstance = hostInstance;
  _port = port;
}

int SFClient::connect(void)
{
  if(!_client->connect(_hostLogin, _port))
  {
    return E_NOCONNECTION;
  }

  return E_OK;
}

int SFClient::authenticate(const char* username, const char* password)
{
  _username = username;
  _password = password;

  String strBuff = "grant_type=password&client_id=" + (String)_clientId +
                   "&client_secret=" + _clientSecret +
                   "&username=" + username +
                   "&password=" + password + _securityToken;

  String request = "POST " + (String)ENDPOINT_TOKEN + " HTTP/1.1\r\n" +
    "Host: " + DEFAULT_HOST_LOGIN + "\r\n" +
    "Content-Type: application/x-www-form-urlencoded\r\n" +
    "Content-Length: " + strBuff.length() + "\r\n\r\n" + strBuff;

  _client->print(request);

  String response = "";
  String chunk = "";
  int limit = 0;
  int sendCount = 0;

  do
  {
    if (_client->connected())
    {
      chunk = _client->readStringUntil('\n');
      response += chunk;
    }
    limit++;
  } while (chunk.length() > 0 && limit < 100);

  if (response.length() > 12)
  {
    String httpCode = response.substring(9, 12);
    if(httpCode == "200")
    {
      String respBody = response.substring(response.indexOf('{'), response.indexOf('}') + 1);
      int retCode = initSettings(respBody);
      if(retCode != 0)
      {
        return -1;
      }

      if(!_client->connect(_hostInstance, _port))
      {
        return E_NOCONNECTION;
      }

      return E_OK;
    }
  }

  return -1;
}

int SFClient::initSettings(String resp)
{
  DynamicJsonBuffer jsonBuffer;
  JsonObject& root = jsonBuffer.parseObject(resp);

  if (!root.success())
  {
    return -1;
  }

  _accessToken = root["access_token"].asString();

  return 0;
}

int SFClient::createRecord(const char* sObjectName, JsonObject& object)
{
  char buff[object.measureLength() + 1];
  object.printTo(buff, sizeof(buff));
  String strBuff(buff);
  strBuff += "\n";

  String request = "POST " + (String)ENDPOINT_SOBJECTS + sObjectName + " HTTP/1.1\r\n" +
    "Authorization: Bearer " + _accessToken + "\r\n" +
    "Host: " + _hostInstance + "\r\n" +
    "X-Prettyprint: 1\r\n"
    "Content-Type: application/json\r\n" +
    "Content-Length: " + strBuff.length() + "\r\n\r\n" + strBuff;

  _client->print(request);

  String response = "";
  String chunk = "";
  int limit = 0;
  int sendCount = 0;

  do
  {
    if (_client->connected())
    {
      chunk = _client->readStringUntil('\n');
      response += chunk;
    }
    limit++;
  } while (chunk.length() > 0 && limit < 100);

  if (response.length() > 12)
  {
    String httpCode = response.substring(9, 12);
    if(httpCode == "201")
    {
      return 0;
    }
    else if(httpCode == "401")
    {
      int retCode = authenticate(_username, _password);
      if(retCode == 0)
      {
        retCode = createRecord(sObjectName, object);
        if(retCode == 0)
        {
          return 0;
        }
      }
    }
  }

  return -1;
}
