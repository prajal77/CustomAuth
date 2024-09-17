using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace CustomAuth.Entities
{
    [Index(nameof(Email),IsUnique =true)]
    public class UserAccount
    {
        [Key]
        public int Id { get; set; }
        [Required(ErrorMessage ="First name is required.")]
        [MaxLength(50,ErrorMessage ="Max 50 characters allowed.")]
        public string FirstName { get; set; }

        [Required(ErrorMessage ="Last name is required")]
        [MaxLength(50, ErrorMessage = "Max 50 characters allowed.")]
        public string LastName { get; set; }


        [Required(ErrorMessage = "Email is required")]
        [DataType(DataType.EmailAddress)]
        [MaxLength(100, ErrorMessage = "Max 50 characters allowed.")]
        public string Email { get; set; }

        [Required(ErrorMessage ="Username is required")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }

       
    }
}
