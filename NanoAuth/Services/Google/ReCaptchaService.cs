using Microsoft.AspNetCore.Http;
using NanoAuth.Google.ReCaptcha;
using NanoAuth.Settings.Google;
using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;
using System.Net.Http;
using System.Threading.Tasks;

namespace NanoAuth.Services.Google
{
    public class ReCaptchaService : IReCaptchaService
    {
        public static bool UseRecaptchaNet { get; set; } = false;
        public static HttpClient Client { get; private set; }
        public readonly ReCaptchaSettings ReCaptchaSettings;

        public ReCaptchaService(ReCaptchaSettings settings)
        {
            ReCaptchaSettings = settings;

            if (Client == null)
                Client = new HttpClient();
        }

        public ReCaptchaService(ReCaptchaSettings settings, HttpClient client)
        {
            ReCaptchaSettings = settings;
            Client = client;
        }

        public async Task<ReCaptchaResponse> ValidateAsync(HttpRequest request, bool antiForgery = true)
        {
            if (!request.Form.ContainsKey("g-recaptcha-response")) // error if no reason to do anything, this is to alert developers they are calling it without reason.
                throw new ValidationException("Google reCaptcha response not found in form. Did you forget to include it?");

            var domain = UseRecaptchaNet ? "www.recaptcha.net" : "www.google.com";
            var response = request.Form["g-recaptcha-response"];
            var result = await Client.GetStringAsync($"https://{domain}/recaptcha/api/siteverify?secret={ReCaptchaSettings.SecretKey}&response={response}");
            var captchaResponse = JsonConvert.DeserializeObject<ReCaptchaResponse>(result);

            if (!captchaResponse.success || !antiForgery) return captchaResponse;
            if (captchaResponse.hostname?.ToLower() != request.Host.Host?.ToLower())
                throw new ValidationException("reCaptcha host, and request host do not match. Forgery attempt?");

            return captchaResponse;
        }

        public async Task<ReCaptchaResponse> ValidateAsync(string responseCode)
        {
            if (string.IsNullOrEmpty(responseCode))
                throw new ValidationException("Google reCaptcha response is empty?");

            var domain = UseRecaptchaNet ? "www.recaptcha.net" : "www.google.com";
            var result = await Client.GetStringAsync($"https://{domain}/recaptcha/api/siteverify?secret={ReCaptchaSettings.SecretKey}&response={responseCode}");
            var captchaResponse = JsonConvert.DeserializeObject<ReCaptchaResponse>(result);
            return captchaResponse;
        }
    }
}