using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

namespace FlexApi.Demo
{
    public static class Program
    {
        static void Main(string[] args)
        {
            var cybsHttpClient = new CybsHttpClient();

            var sessionBody = GetSessionBody();
            var context = cybsHttpClient.Post(sessionBody, "/flex/v2/sessions");

            var handler = new JwtSecurityTokenHandler();
            context = context.Replace("\"", string.Empty, System.StringComparison.InvariantCultureIgnoreCase);
            var jsonToken = handler.ReadToken(context);
            var securityToken = jsonToken as JwtSecurityToken;
            var flx = securityToken.Claims.First(claim => claim.Type == "flx").Value;
            var obj = JsonConvert.DeserializeObject<JObject>(flx);
            var jwk = obj.SelectToken("jwk");
            var kid = securityToken.Header["kid"];

            var publicKey = cybsHttpClient.Get($"/flex/v2/public-keys/{kid}");
            var jwk2 = JsonConvert.DeserializeObject<JObject>(publicKey);

            var payload = GetPaymentBody("4111111111111111", context);

            var token = WithJoseJWE(jwk, jwk2, payload, context);
            var flexToken = cybsHttpClient.Post(token, "/flex/v2/tokens", "application/jwt");
            Console.WriteLine("WithJoseJWE");
            Console.WriteLine(flexToken);

            token = WithJoseJWT(jwk, jwk2, payload, context);
            flexToken = cybsHttpClient.Post(token, "/flex/v2/tokens", "application/jwt");
            Console.WriteLine("WithJoseJWT");
            Console.WriteLine(flexToken);

            token = WithChilkat(jwk, jwk2, payload, context);
            flexToken = cybsHttpClient.Post(token, "/flex/v2/tokens", "application/jwt");
            Console.WriteLine("WithJoseJWT");
            Console.WriteLine(flexToken);

            Console.WriteLine("Press any key ...");
            Console.ReadLine();
        }

        private static string WithJoseJWE(JToken jwk, JToken jwk2, string payload, string context)
        {
            var keys = "{\n" +
                        "  \"keys\": [\n" +
                        $"    {jwk.ToString()},\n" +
                        $"    {jwk2.ToString()}\n" +
                        "  ]\n" +
                        "}\n";
            var keySet = Jose.JwkSet.FromJson(keys, Jose.JWT.DefaultSettings.JsonMapper);
            var encryptionKey = jwk.SelectToken("kid").ToString();

            var headers = new Dictionary<string, object>();
            headers.Add("kid", encryptionKey);
            var recipients = new List<Jose.JweRecipient>();
            recipients.Add(new Jose.JweRecipient(Jose.JweAlgorithm.RSA_OAEP, keySet.Keys[0], header: headers));

            return Jose.JWE.Encrypt(payload, recipients, Jose.JweEncryption.A256GCM, mode: Jose.SerializationMode.Compact);
        }

        private static string WithJoseJWT(JToken jwk, JToken jwk2, string payload, string context)
        {
            var keys = "{\n" +
                        "  \"keys\": [\n" +
                        $"    {jwk.ToString()},\n" +
                        $"    {jwk2.ToString()}\n" +
                        "  ]\n" +
                        "}\n";
            var keySet = Jose.JwkSet.FromJson(keys, Jose.JWT.DefaultSettings.JsonMapper);
            var encryptionKey = jwk.SelectToken("kid").ToString();

            var headers = new Dictionary<string, object>();
            headers.Add("kid", encryptionKey);
            return Jose.JWT.Encode(payload, keySet.Keys[0], Jose.JweAlgorithm.RSA_OAEP, Jose.JweEncryption.A256GCM, extraHeaders: headers);
        }

        private static string WithChilkat(JToken jwk, JToken jwk2, string payload, string context)
        {
            var jweProtHdr = new Chilkat.JsonObject();
            jweProtHdr.AppendString("alg", "RSA-OAEP");
            jweProtHdr.AppendString("enc", "A256GCM");
            jweProtHdr.AppendString("kid", jwk.SelectToken("kid").ToString());

            var rsaPrivKey = new Chilkat.PrivateKey();
            var success = rsaPrivKey.LoadJwk(jwk.ToString());
            Console.WriteLine($"rsaPrivKey.LoadJwk: {success}");
            var rsaPubKey = rsaPrivKey.GetPublicKey();

            var jwe = new Chilkat.Jwe();
            jwe.SetProtectedHeader(jweProtHdr);
            success = jwe.SetPublicKey(0, rsaPubKey);

            return jwe.Encrypt(payload, "utf-8");
        }

        private static string GetPaymentBody(string number, string context)
        {
            return
                    "{\n" +
                    "\"data\": {\n" +
                    "  \"paymentInformation\": {\n" +
                    "    \"card\": {\n" +
                    "      \"number\": \"" + number + "\"\n" +
                    "    }\n" +
                    "  }\n" +
                    "},\n" +
                    "\"context\": \"" + context + "\",\n" +
                    "\"index\": 0\n" +
                    "}";
        }

        private static string GetSessionBody()
        {
            var body = "{\n" +
                        "  \"fields\" : {\n" +
                        "    \"paymentInformation\" : {\n" +
                        "      \"card\" : {\n" +
                        "        \"number\" : { },\n" +
                        "        \"securityCode\" : {\n" +
                        "          \"required\" : false\n" +
                        "        },\n" +
                        "        \"expirationMonth\" : {\n" +
                        "          \"required\" : false\n" +
                        "        },\n" +
                        "        \"expirationYear\" : {\n" +
                        "          \"required\" : false\n" +
                        "        },\n" +
                        "        \"type\" : {\n" +
                       "          \"required\" : false\n" +
                        "        }\n" +
                        "      }\n" +
                        "    }\n" +
                        "  }\n" +
                        "}";
            return body;
        }
    }
}

