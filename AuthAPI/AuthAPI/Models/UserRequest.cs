namespace AuthAPI.Models
{
    public class UserRequest
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public string? Token { get; set; }
    }
}
