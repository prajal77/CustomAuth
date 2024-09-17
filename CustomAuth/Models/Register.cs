using System.ComponentModel.DataAnnotations;

namespace CustomAuth.Models
{
    public class Register
    {
        [Required(ErrorMessage = "First name is required.")]
        [MaxLength(50, ErrorMessage = "Max 50 characters allowed.")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "Last name is required")]
        [MaxLength(50, ErrorMessage = "Max 50 characters allowed.")]
        public string LastName { get; set; }


        [Required(ErrorMessage = "Email is required")]
        [MaxLength(100, ErrorMessage = "Max 50 characters allowed.")]
        //[EmailAddress(ErrorMessage="Please enter valid Email")]
        [RegularExpression("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", ErrorMessage = "Please enter valid Email")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Username is required")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [StringLength(20, MinimumLength = 5, ErrorMessage = "Max 10 or min 5 characters allowed.")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Compare("Password",ErrorMessage ="Please confirm your password")]
        [StringLength(20, MinimumLength =5, ErrorMessage = "Max 10 or min 5 characters allowed.")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; }
       
      
    }
}
