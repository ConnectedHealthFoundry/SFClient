#include "SFClient.h"

static const int E_OK = 0;
static const int E_NOCONNECTION = -1;
static const int E_UNAUTHORIZED = -2;
static const int E_SOBJECT_ERROR = -3;

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

int SFClient::connect(const char *host, int port)
{
  if(!_client->connect(host, port))
  {
    return E_NOCONNECTION;
  }

  return E_OK;
}

String SFClient::getHttpCode(String resp)
{
  int periodIndex = resp.indexOf('.');
  return resp.substring(periodIndex + 3, periodIndex + 6);
}

int SFClient::authenticate(const char* username, const char* password)
{
  connect(_hostLogin);
  while(!_client->connected())
  {
    connect(_hostLogin);
  }

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

  String response = "";
  String chunk = "";
  int limit = 0;
  int sendCount = 0;

  _client->print(request);
  do
  {
    if (_client->connected())
    {
      chunk = _client->readStringUntil('\n');
      response += chunk;
    }
    limit++;
  } while (chunk.length() > 0 && limit < 100);
  close();

  if (response.length() > 12)
  {
    String httpCode = getHttpCode(response);
    if(httpCode == "200")
    {
      String respBody = response.substring(response.indexOf('{'), response.indexOf('}') + 1);
      int retCode = initSettings(respBody);
      if(retCode != E_OK)
      {
        return E_UNAUTHORIZED;
      }

      return E_OK;
    }
  }

  return E_UNAUTHORIZED;
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

  return E_OK;
}

int SFClient::createRecord(const char* sObjectName, JsonObject& object)
{
  connect(_hostInstance);
  while(!_client->connected())
  {
    connect(_hostInstance);
  }

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

  String response = "";
  String chunk = "";
  int limit = 0;
  int sendCount = 0;

  _client->print(request);
  do
  {
    if (_client->connected())
    {
      chunk = _client->readStringUntil('\n');
      response += chunk;
    }
    limit++;
  } while (chunk.length() > 0 && limit < 100);
  close();

  if (response.length() > 12)
  {
    String httpCode = getHttpCode(response);
    if(httpCode == "201")
    {
      return E_OK;
    }
    else if(httpCode == "401")
    {
      Serial.println(response);

      if(connect(_hostLogin) != E_OK)
      {
        return E_NOCONNECTION;
      }

      if(authenticate(_username, _password) != E_OK)
      {
        return E_UNAUTHORIZED;
      }

      if(createRecord(sObjectName, object) == E_OK)
      {
        return E_OK;
      }
    }
  }
  Serial.println(response);

  return E_SOBJECT_ERROR;
}

void SFClient::close(void)
{
  _client->flush();
  _client->stop();
}
