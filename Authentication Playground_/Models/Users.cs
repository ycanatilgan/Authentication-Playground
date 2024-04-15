using System.ComponentModel.DataAnnotations;

namespace Authentication_Playground_.Models
{
    public class Users
    {
        [Key]
        public int Id { get; set; }
        [Required]
        [MaxLength(50)]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
        public string? MFASecret { get; set; }
        public string? UserHandle { get; set; }
    }
}
