using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using NanoAuth.Google.ReCaptcha;

namespace NanoAuth.Services.Google
{
    public interface IReCaptchaService
    {
        Task<ReCaptchaResponse> ValidateAsync(HttpRequest request, bool antiForgery = true);

        Task<ReCaptchaResponse> ValidateAsync(string responseCode);
    }
}