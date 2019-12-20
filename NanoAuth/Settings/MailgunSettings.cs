namespace NanoAuth.Settings
{
    public class MailgunSettings : ISettings
    {
        public string BaseUrl { get; set; }
        public string Domain { get; set; }
        public string Key { get; set; }
    }
}