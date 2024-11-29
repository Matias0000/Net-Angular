using System.ComponentModel.DataAnnotations;

namespace CRUD_Angular_16.Models
{
    public class User
    {
        public int Id { get; set; } 
        [Required]
        public string Username { get; set; }
        [Required]
        public string Email { get; set; } 
        [Required]
        public string PasswordHash { get; set; }
        public string Role { get; set; } 
    }
}
