using System.ComponentModel.DataAnnotations;

namespace Identity_II.Models;

public class RegisterUser
{
    public string UserName {get;set;}
    public string Email {get;set;}
    [Required]
    public string Password {get;set;}
}