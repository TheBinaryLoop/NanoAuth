using Microsoft.AspNetCore.Mvc;

namespace NanoAuth.Models.Account
{
    public class ConfirmEmailViewModel
    {
        [TempData]
        public string StatusMessage { get; set; }
    }
}