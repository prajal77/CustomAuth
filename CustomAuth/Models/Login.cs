using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace CustomAuth.Models
{
    public class Login
    {
        [Required(ErrorMessage = "Email is required")]
        [MaxLength(100, ErrorMessage = "Max 50 characters allowed.")]
        //[EmailAddress(ErrorMessage="Please enter valid Email")]
        public string Email { get; set; }

        //to enter username or email

        /*[Required(ErrorMessage = "Email is required")]
        [MaxLength(100, ErrorMessage = "Max 50 characters allowed.")]
        //[EmailAddress(ErrorMessage="Please enter valid Email")]
        [DisplayName("UserName or Email")]
        public string EmailOrUserName { get; set; }*/

        [Required(ErrorMessage = "Password is required")]
        [StringLength(20, MinimumLength = 5, ErrorMessage = "Max 10 or min 5 characters allowed.")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
