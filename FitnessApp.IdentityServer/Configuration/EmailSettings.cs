namespace FitnessApp.IdentityServer.Configuration
{
    public class EmailSettings
    {
        public string SenderEmail { get; set; }
        public string SenderPassword { get; set; }
        public string Smtp { get; set; }
        public int Port { get; set; }
        public bool UseSsl { get; set; }
    }
}
