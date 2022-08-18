namespace FlexApi.Demo
{
    using System;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;

    public class CybsHttpClient
    {
        private readonly string merchantId = "axa_retail_ecom_sit";

        private readonly string runEnv = "apitest.cybersource.com";

        private readonly string secretKey = <will be sent in separate message>;

        private readonly string keyId = "3ea190d9-be22-46e6-b2e4-fc3cd8250ce4";

        public string Post(string body, string resource, string contentType = "application/json")
        {
            string responseContent = string.Empty;
            using (var client = new HttpClient())
            {
                using (var content = new StringContent(body))
                {
                    content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
                    client.DefaultRequestHeaders.Add("v-c-merchant-id", this.merchantId);
                    var gmtDateTime = DateTime.Now.ToUniversalTime().ToString("r");
                    client.DefaultRequestHeaders.Add("Date", gmtDateTime);
                    client.DefaultRequestHeaders.Add("Host", this.runEnv);
                    var digest = GenerateDigest(body);
                    client.DefaultRequestHeaders.Add("Digest", digest);
                    StringBuilder signature = this.GenerateSignature(digest, gmtDateTime, "post", resource, this.merchantId);
                    client.DefaultRequestHeaders.Add("Signature", signature.ToString());
                    var response = client.PostAsync("https://" + this.runEnv + resource, content).Result;
                    var responseCode = (TaskStatus)response.StatusCode;
                    responseContent = response.Content.ReadAsStringAsync().Result;
                }
            }

            return responseContent;
        }

        public string Get(string resource)
        {
            string gmtDateTime = DateTime.Now.ToUniversalTime().ToString("r");

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("v-c-merchant-id", merchantId);
                client.DefaultRequestHeaders.Add("Date", gmtDateTime);
                client.DefaultRequestHeaders.Add("Host", this.runEnv);

                StringBuilder signature = this.GenerateSignature(gmtDateTime, resource, merchantId);
                client.DefaultRequestHeaders.Add("Signature", signature.ToString());

                var url = new Uri($"https://{this.runEnv}{resource}");
                var response = client.GetAsync(url).Result;
                var content = response.Content.ReadAsStringAsync().Result;
                return content;
            }
        }

        private StringBuilder GenerateSignature(string digest, string gmtDateTime, string method, string resource, string merchantId)
        {
            StringBuilder signatureHeaderValue = new StringBuilder();
            string algorithm = "HmacSHA256";
            string postHeaders = "host date (request-target) digest v-c-merchant-id";
            string getHeaders = "host date (request-target) v-c-merchant-id";
            string getRequestTarget = method + " " + resource;
            string postRequestTarget = method + " " + resource;

            try
            {
                StringBuilder signatureString = new StringBuilder();
                signatureString.Append('\n');
                signatureString.Append("host");
                signatureString.Append(": ");
                signatureString.Append(this.runEnv);
                signatureString.Append('\n');
                signatureString.Append("date");
                signatureString.Append(": ");
                signatureString.Append(gmtDateTime);
                signatureString.Append('\n');
                signatureString.Append("(request-target)");
                signatureString.Append(": ");

                if (method.Equals("post"))
                {
                    signatureString.Append(postRequestTarget);
                    signatureString.Append('\n');
                    signatureString.Append("digest");
                    signatureString.Append(": ");
                    signatureString.Append(digest);
                }
                else
                {
                    signatureString.Append(getRequestTarget);
                }

                signatureString.Append('\n');
                signatureString.Append("v-c-merchant-id");
                signatureString.Append(": ");
                signatureString.Append(merchantId);
                signatureString.Remove(0, 1);

                byte[] signatureByteString = Encoding.UTF8.GetBytes(signatureString.ToString());

                byte[] decodedKey = Convert.FromBase64String(this.secretKey);

                HMACSHA256 aKeyId = new HMACSHA256(decodedKey);

                byte[] hashmessage = aKeyId.ComputeHash(signatureByteString);
                string base64EncodedSignature = Convert.ToBase64String(hashmessage);

                signatureHeaderValue.Append("keyid=\"" + this.keyId + "\"");
                signatureHeaderValue.Append(", algorithm=\"" + algorithm + "\"");

                if (method.Equals("post"))
                {
                    signatureHeaderValue.Append(", headers=\"" + postHeaders + "\"");
                }
                else if (method.Equals("get"))
                {
                    signatureHeaderValue.Append(", headers=\"" + getHeaders + "\"");
                }

                signatureHeaderValue.Append(", signature=\"" + base64EncodedSignature + "\"");
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR : " + ex.ToString());
            }

            return signatureHeaderValue;
        }

        private StringBuilder GenerateSignature(string gmtDateTime, string resource, string merchantId)
        {
            StringBuilder signatureHeaderValue = new StringBuilder();
            string algorithm = "HmacSHA256";
            string getHeaders = "host date (request-target) v-c-merchant-id";
            string getRequestTarget = $"get {resource}";

            StringBuilder signatureString = new StringBuilder();
            signatureString.Append('\n');
            signatureString.Append("host");
            signatureString.Append(": ");
            signatureString.Append(this.runEnv);
            signatureString.Append('\n');
            signatureString.Append("date");
            signatureString.Append(": ");
            signatureString.Append(gmtDateTime);
            signatureString.Append('\n');
            signatureString.Append("(request-target)");
            signatureString.Append(": ");
            signatureString.Append(getRequestTarget);
            signatureString.Append('\n');
            signatureString.Append("v-c-merchant-id");
            signatureString.Append(": ");
            signatureString.Append(merchantId);
            signatureString.Remove(0, 1);

            byte[] signatureByteString = Encoding.UTF8.GetBytes(signatureString.ToString());

            byte[] decodedKey = Convert.FromBase64String(this.secretKey);

            using (var aKeyId = new HMACSHA256(decodedKey))
            {
                byte[] hashmessage = aKeyId.ComputeHash(signatureByteString);
                string base64EncodedSignature = Convert.ToBase64String(hashmessage);

                signatureHeaderValue.Append("keyid=\"" + this.keyId + "\"");
                signatureHeaderValue.Append(", algorithm=\"" + algorithm + "\"");
                signatureHeaderValue.Append(", headers=\"" + getHeaders + "\"");
                signatureHeaderValue.Append(", signature=\"" + base64EncodedSignature + "\"");
            }

            return signatureHeaderValue;
        }

        private static string GenerateDigest(string body)
        {
            var digest = "DIGEST_PLACEHOLDER";
            try
            {
                using (var sha256Hash = SHA256.Create())
                {
                    byte[] payloadBytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(body));
                    digest = Convert.ToBase64String(payloadBytes);
                    digest = "SHA-256=" + digest;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR : " + ex.ToString());
            }

            return digest;
        }
    }
}

